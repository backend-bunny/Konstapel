package cache

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// The documented defaults (docs/policy-bundles.md).
func TestDefaultLimitsMatchDocs(t *testing.T) {
	want := Limits{
		MaxManifestBytes: 4 << 20, MaxCompressedBytes: 64 << 20, MaxUnpackedBytes: 256 << 20,
		MaxFiles: 4096, MaxDescriptorBytes: 4 << 20, MaxPathBytes: 1024, MaxNameBytes: 255,
		MaxDepth: 32, MaxProofBytes: 16 << 20, CapacityBytes: 1 << 30,
	}
	if got := DefaultLimits(); got != want {
		t.Fatalf("defaults %+v, documented %+v", got, want)
	}
	if err := want.Validate(); err != nil {
		t.Fatal(err)
	}
	// A maximal entry with its staging and its verification material fits
	// the default capacity about 2.75 times over; the bound itself is
	// documented as ~372 MiB.
	if w := want.worstCaseReservation(); w > want.CapacityBytes/2 || w < 372<<20 || w > 373<<20 {
		t.Fatalf("worst case %d", w)
	}
}

func TestLimitsValidate(t *testing.T) {
	mod := func(f func(*Limits)) Limits { l := DefaultLimits(); f(&l); return l }
	bad := map[string]Limits{
		"zero manifest":         mod(func(l *Limits) { l.MaxManifestBytes = 0 }),
		"negative compressed":   mod(func(l *Limits) { l.MaxCompressedBytes = -1 }),
		"zero unpacked":         mod(func(l *Limits) { l.MaxUnpackedBytes = 0 }),
		"zero files":            mod(func(l *Limits) { l.MaxFiles = 0 }),
		"absurd files":          mod(func(l *Limits) { l.MaxFiles = 1 << 30 }),
		"absurd bytes":          mod(func(l *Limits) { l.MaxUnpackedBytes = 1 << 50 }),
		"zero descriptor":       mod(func(l *Limits) { l.MaxDescriptorBytes = 0 }),
		"descriptor > unpacked": mod(func(l *Limits) { l.MaxUnpackedBytes = 1 << 20; l.MaxDescriptorBytes = 2 << 20 }),
		"name > 255":            mod(func(l *Limits) { l.MaxNameBytes = 256 }),
		"path < name":           mod(func(l *Limits) { l.MaxPathBytes = 100 }),
		"path too long":         mod(func(l *Limits) { l.MaxPathBytes = 4096 }),
		"zero depth":            mod(func(l *Limits) { l.MaxDepth = 0 }),
		"zero capacity":         mod(func(l *Limits) { l.CapacityBytes = 0 }),
		"zero proofs":           mod(func(l *Limits) { l.MaxProofBytes = 0 }),
		"proofs above recheck":  mod(func(l *Limits) { l.MaxProofBytes = 16<<20 + 1 }),
		"capacity below proofs": mod(func(l *Limits) { l.CapacityBytes = l.worstCaseReservation() - 1 }),
		"capacity below entry":  mod(func(l *Limits) { l.CapacityBytes = 300 << 20 }),
	}
	for name, l := range bad {
		t.Run(name, func(t *testing.T) {
			if err := l.Validate(); !errors.Is(err, ErrConfig) {
				t.Fatalf("got %v", err)
			}
			e := newEnv(t)
			before := e.snapshot(t)
			if _, err := Open(e.root, Config{Limits: l}); !errors.Is(err, ErrConfig) {
				t.Fatalf("Open: %v", err)
			}
			sameSnapshot(t, before, e.snapshot(t))
		})
	}
}

// One Cache owns a root; a second Open fails until the first closes.
func TestLockIsExclusive(t *testing.T) {
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	if _, err := Open(e.root, Config{}); !errors.Is(err, ErrInUse) {
		t.Fatalf("second open: %v", err)
	}
	must(t, c.Close())
	if _, err := c.Put(bg(), small(t, 0).Manifest, small(t, 0).Layer); !errors.Is(err, ErrClosed) {
		t.Fatalf("put after close: %v", err)
	}
	e.open(t, Config{})
}

// An observer polling the final path never sees a partial entry: it is
// either absent or complete.
func TestPromotionIsAtomic(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		c := e.open(t, Config{CheckContent: noCheck})
		a := small(t, i)
		final := filepath.Join(e.root, contentDir, a.ManifestDigest[7:])
		want := len(a.Descriptor.Files) + 1
		stop := make(chan struct{})
		var bad atomic.Value
		var seen atomic.Bool
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := os.Lstat(final); err != nil {
					runtime.Gosched()
					continue
				}
				seen.Store(true)
				if _, err := os.Stat(filepath.Join(final, recordName)); err != nil {
					bad.Store("visible without record")
				}
				if n := len(readTreeLoose(final + "/tree")); n != want {
					bad.Store(fmt.Sprintf("visible with %d of %d files", n, want))
				}
			}
		}()
		if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
			t.Fatal(err)
		}
		// The entry exists now; let the observer look at the promoted entry
		// at least once before it is stopped. A fixed short sleep is not
		// enough on a loaded runner, where the observer may not be scheduled
		// for a while; bound the wait instead of assuming it.
		for deadline := time.Now().Add(10 * time.Second); !seen.Load() && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
		close(stop)
		wg.Wait()
		if v := bad.Load(); v != nil {
			t.Fatal(v)
		}
		if !seen.Load() {
			t.Fatal("observer never saw the entry")
		}
		must(t, c.Close())
	}
}

func readTreeLoose(dir string) []string {
	var out []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// Ordering of the commit: every staged file is synced before its
// directory, every directory before the entry is renamed, blobs are renamed
// and blobs/ synced before the entry rename, and content/ is synced after it.
func TestCommitOrdering(t *testing.T) {
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
	start := len(ffs.log())
	a := small(t, 0)
	if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
		t.Fatal(err)
	}
	ops := ffs.log()[start:]
	index := func(pred func(string) bool) int {
		for i, op := range ops {
			if pred(op) {
				return i
			}
		}
		return -1
	}
	commit := index(func(op string) bool {
		return strings.HasPrefix(op, "rename ") && strings.Contains(op, "-> "+contentDir+"/")
	})
	if commit < 0 {
		t.Fatalf("no commit rename in %v", ops)
	}
	created := map[string]bool{}
	synced := map[string]int{}
	for i, op := range ops[:commit] {
		f := strings.SplitN(op, " ", 2)
		switch f[0] {
		case "create", "mkdir":
			created[f[1]] = true
		case "sync", "syncdir":
			synced[f[1]] = i
		}
	}
	for p := range created {
		if _, ok := synced[p]; !ok {
			t.Errorf("%s created but not synced before the commit", p)
		}
		if dir := filepath.Dir(p); created[dir] {
			if synced[dir] < synced[p] {
				t.Errorf("%s synced before its child %s", dir, p)
			}
		}
	}
	blobRenames := 0
	for _, op := range ops[:commit] {
		if strings.HasPrefix(op, "rename ") && strings.Contains(op, "-> "+blobsDir+"/") {
			blobRenames++
		}
	}
	if blobRenames != 2 {
		t.Errorf("%d blob renames before the commit", blobRenames)
	}
	if i := index(func(op string) bool { return op == "syncdir "+blobsDir }); i < 0 || i > commit {
		t.Errorf("blobs dir synced at %d, commit at %d", i, commit)
	}
	if i := index(func(op string) bool { return op == "syncdir "+contentDir }); i < commit {
		t.Errorf("content dir synced at %d, commit at %d", i, commit)
	}
	// Verification read the staged tree before the commit.
	if i := index(func(op string) bool {
		return strings.HasPrefix(op, "open staging/") && strings.Contains(op, "/entry/tree/")
	}); i < 0 || i > commit {
		t.Errorf("staged tree not verified before the commit")
	}
}

// Every write lands under a fresh random staging directory, never at a
// path derived from the archive, and only renames reach blobs/ and content/.
func TestStagingIsPrivate(t *testing.T) {
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
	start := len(ffs.log())
	for i := 0; i < 2; i++ {
		if _, err := c.Put(bg(), small(t, i).Manifest, small(t, i).Layer); err != nil {
			t.Fatal(err)
		}
	}
	stage := regexp.MustCompile(`^staging/[0-9a-f]{32}(/|$)`)
	dirs := map[string]bool{}
	for _, op := range ffs.log()[start:] {
		f := strings.SplitN(op, " ", 2)
		switch f[0] {
		case "create", "mkdir", "write", "sync":
			if !stage.MatchString(f[1]) {
				t.Errorf("%s outside staging", op)
			}
			if f[0] == "mkdir" && strings.Count(f[1], "/") == 1 {
				if dirs[f[1]] {
					t.Errorf("staging directory %s reused", f[1])
				}
				dirs[f[1]] = true
			}
		case "rename":
			from := strings.SplitN(f[1], " -> ", 2)[0]
			if !stage.MatchString(from) {
				t.Errorf("%s renames from outside staging", op)
			}
		}
	}
	if len(dirs) != 2 {
		t.Fatalf("staging dirs %v", dirs)
	}
}

// Interrupt the process at every mutating step of a Put: the next Open
// cleans staging and orphan blobs, no partial entry is ever promoted, the
// accounting matches the disk, and a retry succeeds.
func TestInterruptAtEveryStep(t *testing.T) {
	a := small(t, 0)
	existing := small(t, 1)
	// Count the mutating steps of one Put.
	var total int
	{
		e := newEnv(t)
		var ffs *faultFS
		c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
		before := ffs.mutates
		if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
			t.Fatal(err)
		}
		total = ffs.mutates - before
	}
	if total < 20 {
		t.Fatalf("only %d steps", total)
	}
	for k := 1; k <= total+1; k++ {
		t.Run(fmt.Sprint(k), func(t *testing.T) {
			e := newEnv(t)
			c := e.open(t, Config{CheckContent: noCheck})
			if _, err := c.Put(bg(), existing.Manifest, existing.Layer); err != nil {
				t.Fatal(err)
			}
			must(t, c.Close())
			var ffs *faultFS
			c = e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
			ffs.crashAt = ffs.mutates + k
			_, putErr := c.Put(bg(), a.Manifest, a.Layer)
			must(t, c.Close()) // the "dead" process lets go of its lock
			// The last step is the best-effort removal of the emptied
			// staging directory after the commit; Open removes it instead.
			if (k < total) != (putErr != nil) {
				t.Fatalf("crash at step %d of %d: Put returned %v", k, total, putErr)
			}

			c2 := e.open(t, Config{CheckContent: noCheck})
			assertIdle(t, c2)
			if _, err := c2.Get(bg(), existing.ManifestDigest); err != nil {
				t.Fatalf("existing entry after crash at %d: %v", k, err)
			}
			got, err := c2.Get(bg(), a.ManifestDigest)
			switch {
			case err == nil:
				if err := got.Descriptor.VerifyPayload(got.FS()); err != nil {
					t.Fatalf("promoted entry incomplete: %v", err)
				}
			case errors.Is(err, ErrNotFound):
			default:
				t.Fatalf("after crash at %d: %v", k, err)
			}
			checkAccounting(t, c2)
			// Nothing but tracked blobs remains.
			blobs, _ := os.ReadDir(filepath.Join(e.root, blobsDir))
			if n := len(c2.blobs); len(blobs) != n {
				t.Fatalf("%d blobs on disk, %d tracked", len(blobs), n)
			}
			if _, err := c2.Put(bg(), a.Manifest, a.Layer); err != nil {
				t.Fatalf("retry: %v", err)
			}
			checkAccounting(t, c2)
			assertIdle(t, c2)
		})
	}
}

// checkAccounting compares the charge with a fresh recount from disk.
func checkAccounting(t *testing.T, c *Cache) {
	t.Helper()
	s := c.Stats()
	var sum int64
	for _, b := range c.blobs {
		sum += b.cost
	}
	for _, en := range c.entries {
		sum += en.cost
		if en.proofs != nil {
			sum += en.proofs.cost
		}
	}
	if s.UsedBytes != sum {
		t.Fatalf("used %d, components %d", s.UsedBytes, sum)
	}
	var disk int64
	must(t, filepath.WalkDir(filepath.Join(c.dir, contentDir), func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == filepath.Join(c.dir, contentDir) {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			disk += blockSize
		} else {
			disk += blocks(info.Size())
		}
		return nil
	}))
	for _, dir := range []string{blobsDir, proofsDir} {
		files, err := os.ReadDir(filepath.Join(c.dir, dir))
		must(t, err)
		for _, b := range files {
			info, err := b.Info()
			must(t, err)
			disk += blocks(info.Size())
		}
	}
	if disk != s.UsedBytes {
		t.Fatalf("disk charge %d, accounted %d", disk, s.UsedBytes)
	}
}

// Concurrent identical Puts converge on one entry.
func TestConcurrentIdenticalPuts(t *testing.T) {
	e := newEnv(t)
	const putters = 16
	var stages, started atomic.Int32
	var ffs *faultFS
	c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
	ffs.hook = func(op, name string) error {
		if op == "mkdir" && strings.Count(name, "/") == 1 && strings.HasPrefix(name, stagingDir+"/") {
			stages.Add(1)
			// Hold the leader's staging open until every Put has been
			// started, then a moment longer so the followers reach the
			// in-flight join, instead of assuming a fixed delay is enough
			// on a loaded runner.
			for deadline := time.Now().Add(10 * time.Second); started.Load() < putters && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond)
		}
		return nil
	}
	a := small(t, 0)
	var wg sync.WaitGroup
	errs := make([]error, putters)
	dirs := make([]string, putters)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Add(1)
			en, err := c.Put(bg(), a.Manifest, a.Layer)
			errs[i] = err
			if en != nil {
				dirs[i] = en.Dir
			}
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil || dirs[i] != dirs[0] {
			t.Fatalf("put %d: %v %s", i, err, dirs[i])
		}
	}
	if n := stages.Load(); n != 1 {
		t.Fatalf("%d stagings for one digest", n)
	}
	if s := c.Stats(); len(s.Entries) != 1 {
		t.Fatalf("entries %+v", s.Entries)
	}
	checkAccounting(t, c)
	assertIdle(t, c)
}

// When the final path appears while staging (the destination-exists race),
// the staged copy is discarded, the existing entry returned, and nothing is
// replaced. Exercised by bypassing coalescing.
func TestDestinationExistsRace(t *testing.T) {
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	a := small(t, 0)
	h := a.ManifestDigest[7:]
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, errs[i] = c.put(bg(), h, a.Manifest, a.Layer, a.LayerDigest, nil)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if s := c.Stats(); len(s.Entries) != 1 {
		t.Fatalf("entries %+v", s.Entries)
	}
	checkAccounting(t, c)
	assertIdle(t, c)
	first, err := os.Stat(filepath.Join(e.root, contentDir, h))
	must(t, err)
	// Another staged copy over an intact entry leaves it in place.
	if _, _, err := c.put(bg(), h, a.Manifest, a.Layer, a.LayerDigest, nil); err != nil {
		t.Fatal(err)
	}
	again, err := os.Stat(filepath.Join(e.root, contentDir, h))
	must(t, err)
	if !os.SameFile(first, again) {
		t.Fatal("existing entry replaced")
	}
}

// N concurrent distinct leased Puts against a capacity that fits exactly k
// of them: exactly k are promoted, the rest fail with ErrCapacity, and the
// reservation returns to zero.
func TestConcurrentCapacity(t *testing.T) {
	const n, k = 12, 5
	// Measure one entry's charge.
	m0, l0 := variant(t, 0)
	probe := newEnv(t)
	pc := probe.open(t, Config{CheckContent: noCheck})
	en, err := pc.Put(bg(), m0, l0)
	must(t, err)
	cost := en.Bytes
	lim := tinyLimits()
	lim.CapacityBytes = k * (cost + stagingOverhead)
	must(t, lim.Validate())

	for round := 0; round < 3; round++ {
		e := newEnv(t)
		c := e.open(t, Config{Limits: lim, CheckContent: noCheck})
		var wg sync.WaitGroup
		errs := make([]error, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			m, l := variant(t, round*100+i)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// Leased, so that admission alone decides: nothing can be
				// evicted to admit more than k.
				_, _, errs[i] = c.PutLeased(bg(), m, l, bundle.HolderProfile, fmt.Sprint("p", i))
			}()
		}
		close(start)
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrCapacity):
			default:
				t.Fatal(err)
			}
		}
		if ok != k {
			t.Fatalf("%d promoted, want %d", ok, k)
		}
		s := c.Stats()
		if s.ReservedBytes != 0 || s.UsedBytes != k*cost || len(s.Entries) != k || s.UsedBytes > s.CapacityBytes {
			t.Fatalf("stats %+v (entry %d)", s, cost)
		}
		checkAccounting(t, c)
		assertIdle(t, c)
		for _, en := range s.Entries {
			if _, err := c.Get(bg(), en.Digest); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// Capacity exhausted by leased entries: nothing can be evicted, so the
// refusal evicts nothing, writes nothing at all and leaves the entries intact
// and usable.
func TestCapacityExhaustedByEntries(t *testing.T) {
	m0, l0 := variant(t, 0)
	probe := newEnv(t)
	en, err := probe.open(t, Config{CheckContent: noCheck}).Put(bg(), m0, l0)
	must(t, err)
	lim := tinyLimits()
	lim.CapacityBytes = max(2*en.Bytes+stagingOverhead, lim.worstCaseReservation())
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{Limits: lim, CheckContent: noCheck, wrapFS: withFault(&ffs)})
	var stored []string
	for i := 0; ; i++ {
		m, l := variant(t, i)
		got, _, err := c.PutLeased(bg(), m, l, bundle.HolderApplied, fmt.Sprint("owner-", i))
		if errors.Is(err, ErrCapacity) {
			break
		}
		must(t, err)
		stored = append(stored, got.Digest)
	}
	if len(stored) < 2 {
		t.Fatalf("stored %d", len(stored))
	}
	before := e.snapshot(t)
	ops := len(ffs.log())
	m, l := variant(t, 99)
	if _, err := c.Put(bg(), m, l); !errors.Is(err, ErrCapacity) {
		t.Fatalf("got %v", err)
	}
	for _, op := range ffs.log()[ops:] {
		if !strings.HasPrefix(op, "lstat ") && !strings.HasPrefix(op, "open ") && !strings.HasPrefix(op, "readdir ") {
			t.Errorf("refused Put performed %q", op)
		}
	}
	sameSnapshot(t, before, e.snapshot(t))
	assertIdle(t, c)
	for _, d := range stored {
		if _, err := c.Get(bg(), d); err != nil {
			t.Fatal(err)
		}
	}
	// A stored digest is still served without new capacity.
	if _, err := c.Put(bg(), mustVariantManifest(t, 0), mustVariantLayer(t, 0)); err != nil {
		t.Fatal(err)
	}
}

// tinyLimits fit the small bundle with little room, so capacity tests need
// only a few entries.
func tinyLimits() Limits {
	l := DefaultLimits()
	l.MaxManifestBytes, l.MaxCompressedBytes, l.MaxUnpackedBytes, l.MaxDescriptorBytes, l.MaxFiles = 4<<10, 8<<10, 16<<10, 8<<10, 8
	l.MaxProofBytes = 64 << 10
	return l
}

func mustVariantManifest(t *testing.T, i int) []byte { m, _ := variant(t, i); return m }
func mustVariantLayer(t *testing.T, i int) []byte    { _, l := variant(t, i); return l }

// ENOSPC at any write rolls back staging, releases the reservation, returns
// ErrNoSpace and leaves accepted entries intact.
func TestDiskExhaustion(t *testing.T) {
	a := small(t, 0)
	existing := small(t, 1)
	for _, quota := range []int64{0, 1, 100, int64(len(a.Manifest)) + 10, int64(len(a.Manifest) + len(a.Layer) + 100), int64(len(a.Manifest) + len(a.Layer) + 5000)} {
		t.Run(fmt.Sprint(quota), func(t *testing.T) {
			e := newEnv(t)
			var ffs *faultFS
			c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
			if _, err := c.Put(bg(), existing.Manifest, existing.Layer); err != nil {
				t.Fatal(err)
			}
			used := c.Stats().UsedBytes
			before := e.snapshot(t)
			ffs.mu.Lock()
			ffs.quota, ffs.written = quota, 0
			ffs.mu.Unlock()
			if _, err := c.Put(bg(), a.Manifest, a.Layer); !errors.Is(err, ErrNoSpace) || !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("got %v", err)
			}
			sameSnapshot(t, before, e.snapshot(t))
			assertIdle(t, c)
			if s := c.Stats(); s.UsedBytes != used || len(s.Entries) != 1 {
				t.Fatalf("stats %+v", s)
			}
			if _, err := c.Get(bg(), existing.ManifestDigest); err != nil {
				t.Fatal(err)
			}
			ffs.mu.Lock()
			ffs.quota = -1
			ffs.mu.Unlock()
			if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
				t.Fatal(err)
			}
			checkAccounting(t, c)
		})
	}
}

// A panic inside a Put still removes staging and releases the reservation
// and the in-flight slot.
func TestPanicReleases(t *testing.T) {
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
	ffs.hook = func(op, name string) error {
		if op == "write" && strings.Contains(name, "/entry/tree/") {
			ffs.hook = nil
			panic("injected")
		}
		return nil
	}
	a := small(t, 0)
	func() {
		defer func() {
			if r := recover(); r != "injected" {
				t.Fatalf("recovered %v", r)
			}
		}()
		c.Put(bg(), a.Manifest, a.Layer)
	}()
	assertIdle(t, c)
	if len(c.inflight) != 0 {
		t.Fatal("in-flight slot leaked")
	}
	if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
		t.Fatal(err)
	}
}

// A canceled context stops staging and leaves nothing behind.
func TestCanceledPut(t *testing.T) {
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
	ctx, cancel := context.WithCancel(bg())
	ffs.hook = func(op, name string) error {
		if op == "create" && strings.Contains(name, "/entry/tree/") {
			cancel()
		}
		return nil
	}
	before := e.snapshot(t)
	a := small(t, 0)
	if _, err := c.Put(ctx, a.Manifest, a.Layer); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	sameSnapshot(t, before, e.snapshot(t))
	assertIdle(t, c)
}

// Corruption of any stored byte is detected on reuse, both in the running
// cache and after a restart; the entry is removed and never served.
func TestCorruptionDetectedOnReuse(t *testing.T) {
	a := small(t, 0)
	h, lh := a.ManifestDigest[7:], a.LayerDigest[7:]
	tree := func(root string) string { return filepath.Join(root, contentDir, h, treeName) }
	cases := map[string]func(t *testing.T, root string){
		"layer blob byte": func(t *testing.T, root string) {
			must(t, flipFile(filepath.Join(root, blobsDir, lh), 40))
		},
		// The gzip header time is outside the CRC: the layer still decodes
		// identically, so only its digest reveals the change.
		"layer gzip header time": func(t *testing.T, root string) {
			must(t, flipFile(filepath.Join(root, blobsDir, lh), 4))
		},
		"manifest blob byte": func(t *testing.T, root string) {
			must(t, flipFile(filepath.Join(root, blobsDir, h), 5))
		},
		"extracted file byte": func(t *testing.T, root string) {
			must(t, flipFile(filepath.Join(tree(root), "content/policies/p.yaml"), 0))
		},
		"descriptor byte": func(t *testing.T, root string) {
			must(t, flipFile(filepath.Join(tree(root), "bundle.json"), 10))
		},
		"record byte": func(t *testing.T, root string) {
			must(t, flipFile(filepath.Join(root, contentDir, h, recordName), 3))
		},
		"extra file": func(t *testing.T, root string) {
			must(t, os.WriteFile(filepath.Join(tree(root), "content", "extra"), nil, 0o444))
		},
		"extra directory": func(t *testing.T, root string) {
			must(t, os.Mkdir(filepath.Join(tree(root), "content", "extra"), 0o755))
		},
		"missing file": func(t *testing.T, root string) {
			must(t, os.Remove(filepath.Join(tree(root), "LICENSE")))
		},
		"file replaced by symlink": func(t *testing.T, root string) {
			p := filepath.Join(tree(root), "LICENSE")
			must(t, os.Remove(p))
			must(t, os.Symlink("../../../../../unrelated/file", p))
		},
		"writable file": func(t *testing.T, root string) {
			must(t, os.Chmod(filepath.Join(tree(root), "LICENSE"), 0o644))
		},
		"executable file": func(t *testing.T, root string) {
			must(t, os.Chmod(filepath.Join(tree(root), "LICENSE"), 0o555))
		},
		"truncated layer": func(t *testing.T, root string) {
			p := filepath.Join(root, blobsDir, lh)
			must(t, os.Chmod(p, 0o644))
			must(t, os.Truncate(p, 10))
		},
	}
	for name, corrupt := range cases {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%v", name, restart), func(t *testing.T) {
				e := newEnv(t)
				c := e.open(t, Config{CheckContent: noCheck})
				other := small(t, 1)
				for _, b := range [][2][]byte{{a.Manifest, a.Layer}, {other.Manifest, other.Layer}} {
					if _, err := c.Put(bg(), b[0], b[1]); err != nil {
						t.Fatal(err)
					}
				}
				corrupt(t, e.root)
				if restart {
					must(t, c.Close())
					c = e.open(t, Config{CheckContent: noCheck})
				}
				_, err := c.Get(bg(), a.ManifestDigest)
				if restart && errors.Is(err, ErrNotFound) {
					// Open's structural check already removed it.
					if !contains(c.Recovery().Entries, h) {
						t.Fatalf("removed without a report: %+v", c.Recovery())
					}
				} else if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("got %v", err)
				}
				if _, err := c.Get(bg(), a.ManifestDigest); !errors.Is(err, ErrNotFound) {
					t.Fatalf("corrupt entry still present: %v", err)
				}
				if _, err := os.Lstat(filepath.Join(e.root, contentDir, h)); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("corrupt entry left on disk: %v", err)
				}
				if _, err := c.Get(bg(), other.ManifestDigest); err != nil {
					t.Fatalf("unrelated entry: %v", err)
				}
				checkAccounting(t, c)
				// Re-putting the verified bytes restores it.
				if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
					t.Fatal(err)
				}
				if _, err := c.Get(bg(), a.ManifestDigest); err != nil {
					t.Fatal(err)
				}
				checkAccounting(t, c)
				assertIdle(t, c)
			})
		}
	}
}

// A shared layer blob is kept while any entry references it; corruption of
// it is repaired by the next Put of verified bytes.
func TestSharedLayerBlob(t *testing.T) {
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	a := small(t, 0)
	m2 := manifestFor(t, a.Layer, map[string]string{"x": "y"})
	for _, m := range [][]byte{a.Manifest, m2} {
		if _, err := c.Put(bg(), m, a.Layer); err != nil {
			t.Fatal(err)
		}
	}
	checkAccounting(t, c)
	lh := a.LayerDigest[7:]
	must(t, flipFile(filepath.Join(e.root, blobsDir, lh), 30))
	if _, err := c.Get(bg(), a.ManifestDigest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v", err)
	}
	// The other entry shares the corrupt layer and is detected too.
	if _, err := c.Get(bg(), digest(m2)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v", err)
	}
	checkAccounting(t, c)
	if _, err := c.Put(bg(), m2, a.Layer); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
		t.Fatal(err)
	}
	checkAccounting(t, c)
	// Corrupt the shared blob while both entries are indexed; a Put of a
	// third manifest over the same layer repairs it in place.
	must(t, flipFile(filepath.Join(e.root, blobsDir, lh), 30))
	if _, err := c.Put(bg(), manifestFor(t, a.Layer, map[string]string{"x": "z"}), a.Layer); err != nil {
		t.Fatal(err)
	}
	for _, m := range [][]byte{a.Manifest, m2} {
		if _, err := c.Get(bg(), digest(m)); err != nil {
			t.Fatal(err)
		}
	}
	checkAccounting(t, c)
}

// Open removes abandoned staging, orphan blobs, broken entries and stray
// names inside its own directories, and touches nothing else in the root.
func TestOpenRecovers(t *testing.T) {
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	good, broken := small(t, 0), small(t, 1)
	for _, b := range [][2][]byte{{good.Manifest, good.Layer}, {broken.Manifest, broken.Layer}} {
		if _, err := c.Put(bg(), b[0], b[1]); err != nil {
			t.Fatal(err)
		}
	}
	must(t, c.Close())
	root := e.root
	must(t, os.MkdirAll(filepath.Join(root, stagingDir, "abandoned", "entry", "tree"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, stagingDir, "abandoned", "entry", "tree", "f"), []byte("x"), 0o444))
	orphan := strings.Repeat("e", 64)
	must(t, os.WriteFile(filepath.Join(root, blobsDir, orphan), []byte("orphan"), 0o444))
	must(t, os.WriteFile(filepath.Join(root, blobsDir, "not-a-digest"), nil, 0o444))
	must(t, os.Mkdir(filepath.Join(root, contentDir, "junk"), 0o755))
	must(t, os.Remove(filepath.Join(root, contentDir, broken.ManifestDigest[7:], recordName)))
	// Things the cache does not own.
	must(t, os.Mkdir(filepath.Join(root, "lost+found"), 0o700))
	must(t, os.WriteFile(filepath.Join(root, "operator-note"), []byte("keep"), 0o600))
	must(t, os.Symlink("/etc/passwd", filepath.Join(root, "foreign-link")))

	c2 := e.open(t, Config{CheckContent: noCheck})
	r := c2.Recovery()
	if !contains(r.Staging, "abandoned") || !contains(r.Entries, broken.ManifestDigest[7:]) ||
		!contains(r.Blobs, orphan) || !contains(r.Blobs, broken.ManifestDigest[7:]) ||
		!contains(r.Other, blobsDir+"/not-a-digest") || !contains(r.Other, contentDir+"/junk") {
		t.Fatalf("recovery %+v", r)
	}
	if _, err := c2.Get(bg(), good.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"lost+found", "operator-note", "foreign-link"} {
		if _, err := os.Lstat(filepath.Join(root, p)); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	checkAccounting(t, c2)
	assertIdle(t, c2)
	if s := c2.Stats(); len(s.Entries) != 1 {
		t.Fatalf("%+v", s)
	}
}

// Stats exposes what eviction (task 4.4) will need: per-entry charge and
// last use, updated by Get.
func TestStatsBookkeeping(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck, Now: clock})
	a, b := small(t, 0), small(t, 1)
	for _, x := range []struct{ m, l []byte }{{a.Manifest, a.Layer}, {b.Manifest, b.Layer}} {
		if _, err := c.Put(bg(), x.m, x.l); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	now = now.Add(time.Hour)
	mu.Unlock()
	if _, err := c.Get(bg(), b.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	s := c.Stats()
	var total int64
	for _, en := range s.Entries {
		total += en.Bytes
		want := now.Add(-time.Hour)
		if en.Digest == b.ManifestDigest {
			want = now
		}
		if !en.LastUsed.Equal(want) {
			t.Errorf("%s last used %v, want %v", en.Digest, en.LastUsed, want)
		}
	}
	if total != s.UsedBytes {
		t.Fatalf("entry bytes %d, used %d", total, s.UsedBytes)
	}
}

func flipFile(p string, i int64) error {
	if err := os.Chmod(p, 0o644); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	b := make([]byte, 1)
	if _, err := f.ReadAt(b, i); err != nil {
		return err
	}
	b[0] ^= 0x01
	if _, err := f.WriteAt(b, i); err != nil {
		return err
	}
	return os.Chmod(p, 0o444)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
