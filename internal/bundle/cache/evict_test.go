package cache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// clock is a settable test clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) tick()          { c.mu.Lock(); c.now = c.now.Add(time.Second); c.mu.Unlock() }

// removals records OnRemove calls.
type removals struct {
	mu  sync.Mutex
	got []string
}

func (r *removals) add(d string) { r.mu.Lock(); r.got = append(r.got, d); r.mu.Unlock() }
func (r *removals) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.got
	r.got = nil
	slices.Sort(out)
	return out
}

// entryCost is the charge of one small variant entry.
func entryCost(t *testing.T) int64 {
	t.Helper()
	m, l := variant(t, 0)
	en, err := newEnv(t).open(t, Config{CheckContent: noCheck, Limits: tinyLimits()}).Put(bg(), m, l)
	must(t, err)
	return en.Bytes
}

// fitting returns tiny limits whose capacity holds exactly k stored entries
// while one more stages, and k. Lowering it by one entry stays valid.
func fitting(t *testing.T) (Limits, int) {
	t.Helper()
	cost := entryCost(t)
	lim := tinyLimits()
	worst := lim.worstCaseReservation()
	// One entry more than the minimum, so that tests can lower the
	// capacity by one entry and still pass Validate.
	k := int((worst-stagingOverhead+cost-1)/cost) + 1
	lim.CapacityBytes = int64(k)*cost + stagingOverhead
	must(t, lim.Validate())
	return lim, k
}

func digests(t *testing.T, c *Cache) []string {
	t.Helper()
	var out []string
	for _, e := range c.Stats().Entries {
		out = append(out, e.Digest)
	}
	return out
}

func TestLeaseAcquireRelease(t *testing.T) {
	e := newEnv(t)
	clk := newClock()
	c := e.open(t, Config{CheckContent: noCheck, Now: clk.Now})
	a := small(t, 0)
	if _, err := c.Acquire(a.ManifestDigest, bundle.HolderProfile, "p"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lease on a missing entry: %v", err)
	}
	if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string][2]string{
		"unknown holder": {"owner", "p"}, "empty holder": {"", "p"}, "empty owner": {bundle.HolderApplied, ""},
		"long owner": {bundle.HolderApplied, strings.Repeat("o", maxOwnerBytes+1)},
	} {
		if _, err := c.Acquire(a.ManifestDigest, req[0], req[1]); !errors.Is(err, ErrLease) {
			t.Errorf("%s: %v", name, err)
		}
	}
	l1, err := c.Acquire(a.ManifestDigest, bundle.HolderProfile, "profile/a")
	must(t, err)
	l2, err := c.Acquire(a.ManifestDigest, bundle.HolderAssessment, "assessment/x")
	must(t, err)
	l3, err := c.Acquire(a.ManifestDigest, bundle.HolderProfile, "profile/a") // same owner twice: two leases
	must(t, err)
	if l1.ID == l2.ID || l1.ID == l3.ID || l1.Digest != a.ManifestDigest || l1.Holder != bundle.HolderProfile ||
		l1.Owner != "profile/a" || !l1.AcquiredAt.Equal(clk.Now()) {
		t.Fatalf("leases %+v %+v %+v", l1, l2, l3)
	}
	count := func() int { return c.Stats().Leases }
	if n := count(); n != 3 || c.Stats().Entries[0].Leases != 3 {
		t.Fatalf("leases %d", n)
	}
	// Foreign, altered and unknown leases release nothing.
	for name, l := range map[string]bundle.Lease{
		"other owner":  func() bundle.Lease { x := l1; x.Owner = "profile/b"; return x }(),
		"other holder": func() bundle.Lease { x := l1; x.Holder = bundle.HolderApplied; return x }(),
		"other time":   func() bundle.Lease { x := l1; x.AcquiredAt = x.AcquiredAt.Add(time.Nanosecond); return x }(),
		"other digest": func() bundle.Lease { x := l1; x.Digest = small(t, 1).ManifestDigest; return x }(),
		"unknown id":   func() bundle.Lease { x := l1; x.ID = strings.Repeat("0", 32); return x }(),
		"bad digest":   func() bundle.Lease { x := l1; x.Digest = "sha256:xyz"; return x }(),
		"zero":         {},
	} {
		if err := c.Release(l); !errors.Is(err, ErrLease) {
			t.Errorf("%s: %v", name, err)
		}
		if n := count(); n != 3 {
			t.Fatalf("%s released a lease: %d left", name, n)
		}
	}
	must(t, c.Release(l1))
	if err := c.Release(l1); !errors.Is(err, ErrLease) {
		t.Fatalf("double release: %v", err)
	}
	if n := count(); n != 2 {
		t.Fatalf("leases %d", n)
	}
	must(t, c.Release(l3))
	must(t, c.Release(l2))
	if n := count(); n != 0 || c.Stats().Entries[0].Leases != 0 {
		t.Fatalf("leases %d", n)
	}
	// Releasing does not remove the entry.
	if _, err := c.Get(bg(), a.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	// Leases do not survive a restart.
	_, err = c.Acquire(a.ManifestDigest, bundle.HolderApplied, "applied/x")
	must(t, err)
	must(t, c.Close())
	c2 := e.open(t, Config{CheckContent: noCheck})
	if n := c2.Stats().Leases; n != 0 {
		t.Fatalf("leases after restart %d", n)
	}
	if _, err := c.Acquire(a.ManifestDigest, bundle.HolderApplied, "x"); !errors.Is(err, ErrClosed) {
		t.Fatalf("acquire after close: %v", err)
	}
}

// Least-recently-used unleased entries are evicted, exactly as many as the
// new entry needs, ties broken by digest; Get and Acquire count as use.
func TestEvictionOrder(t *testing.T) {
	lim, k := fitting(t)
	clk := newClock()
	var rm removals
	e := newEnv(t)
	c := e.open(t, Config{Limits: lim, CheckContent: noCheck, Now: clk.Now, OnRemove: rm.add})
	var ds []string
	for i := 0; i < k; i++ {
		m, l := variant(t, i)
		en, err := c.Put(bg(), m, l)
		must(t, err)
		ds = append(ds, en.Digest)
		clk.tick()
	}
	if len(c.Stats().Entries) != k {
		t.Fatalf("stored %d of %d", len(c.Stats().Entries), k)
	}
	// Use the oldest: the second-oldest becomes the victim.
	if _, err := c.Get(bg(), ds[0]); err != nil {
		t.Fatal(err)
	}
	clk.tick()
	m, l := variant(t, 100)
	n100, err := c.Put(bg(), m, l)
	must(t, err)
	if got := rm.take(); !slices.Equal(got, []string{ds[1]}) {
		t.Fatalf("evicted %v, want [%s]", got, ds[1])
	}
	if _, err := c.Get(bg(), ds[1]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("evicted entry: %v", err)
	}
	checkAccounting(t, c)
	assertIdle(t, c)
	clk.tick()

	// Acquire counts as use too.
	l2, err := c.Acquire(ds[2], bundle.HolderProfile, "p")
	must(t, err)
	must(t, c.Release(l2))
	clk.tick()

	// Make every remaining entry equally recent: the smallest digest goes.
	c.mu.Lock()
	for _, st := range c.entries {
		st.lastUsed = clk.Now()
	}
	c.mu.Unlock()
	remaining := digests(t, c)
	m, l = variant(t, 101)
	_, err = c.Put(bg(), m, l)
	must(t, err)
	if got := rm.take(); !slices.Equal(got, remaining[:1]) {
		t.Fatalf("tie evicted %v, want %v", got, remaining[:1])
	}
	_ = n100
	checkAccounting(t, c)
	assertIdle(t, c)
}

// With every entry leased, a Put that does not fit fails with ErrCapacity,
// evicts nothing and writes nothing; one unleased entry is evicted even when
// it is the most recently used.
func TestEvictionNeverTouchesLeases(t *testing.T) {
	lim, k := fitting(t)
	clk := newClock()
	var rm removals
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{Limits: lim, CheckContent: noCheck, Now: clk.Now, OnRemove: rm.add, wrapFS: withFault(&ffs)})
	var leases []bundle.Lease
	for i := 0; i < k; i++ {
		m, l := variant(t, i)
		_, ls, err := c.PutLeased(bg(), m, l, bundle.HolderApplied, fmt.Sprint("a", i))
		must(t, err)
		leases = append(leases, ls)
		clk.tick()
	}
	before := e.snapshot(t)
	ops := len(ffs.log())
	m, l := variant(t, 100)
	if _, err := c.Put(bg(), m, l); !errors.Is(err, ErrCapacity) {
		t.Fatalf("got %v", err)
	}
	for _, op := range ffs.log()[ops:] {
		if !strings.HasPrefix(op, "lstat ") && !strings.HasPrefix(op, "open ") && !strings.HasPrefix(op, "readdir ") {
			t.Errorf("refused Put performed %q", op)
		}
	}
	sameSnapshot(t, before, e.snapshot(t))
	if got := rm.take(); len(got) != 0 {
		t.Fatalf("evicted %v", got)
	}
	assertIdle(t, c)
	// Release the newest lease: only that entry is evictable, and it goes.
	newest := leases[k-1]
	must(t, c.Release(newest))
	if _, err := c.Put(bg(), m, l); err != nil {
		t.Fatal(err)
	}
	if got := rm.take(); !slices.Equal(got, []string{newest.Digest}) {
		t.Fatalf("evicted %v, want %s", got, newest.Digest)
	}
	for _, ls := range leases[:k-1] {
		if _, err := c.Get(bg(), ls.Digest); err != nil {
			t.Fatalf("leased entry: %v", err)
		}
	}
	checkAccounting(t, c)
	assertIdle(t, c)
}

// Reopening with a lower capacity keeps every entry; the next admission
// evicts as many unleased entries as it needs, all or none, and pins that
// exceed the capacity fail new admissions without evicting them.
func TestLoweredCapacityAndAllOrNothing(t *testing.T) {
	lim, k := fitting(t)
	if k < 4 {
		t.Fatalf("k=%d too small for this test", k)
	}
	cost := entryCost(t)
	clk := newClock()
	e := newEnv(t)
	c := e.open(t, Config{Limits: lim, CheckContent: noCheck, Now: clk.Now})
	for i := 0; i < k; i++ {
		m, l := variant(t, i)
		_, err := c.Put(bg(), m, l)
		must(t, err)
		clk.tick()
	}
	must(t, c.Close())

	// One entry's worth less: admitting one more needs two victims.
	low := lim
	low.CapacityBytes -= cost
	must(t, low.Validate())
	for _, pinnedButOne := range []bool{true, false} {
		t.Run(fmt.Sprint("pinned-but-one=", pinnedButOne), func(t *testing.T) {
			var rm removals
			c := e.open(t, Config{Limits: low, CheckContent: noCheck, Now: clk.Now, OnRemove: rm.add})
			defer c.Close()
			s := c.Stats()
			if len(s.Entries) != k || s.UsedBytes != int64(k)*cost {
				t.Fatalf("reopen changed entries: %+v", s)
			}
			// Leases do not survive the restart: pin all but one or two.
			free := 2
			if pinnedButOne {
				free = 1
			}
			var held []bundle.Lease
			for i, en := range s.Entries {
				if i < free {
					continue
				}
				ls, err := c.Acquire(en.Digest, bundle.HolderProfile, fmt.Sprint("p", i))
				must(t, err)
				held = append(held, ls)
			}
			before := e.snapshot(t)
			m, l := variant(t, 200)
			_, err := c.Put(bg(), m, l)
			if pinnedButOne {
				if !errors.Is(err, ErrCapacity) {
					t.Fatalf("got %v", err)
				}
				if got := rm.take(); len(got) != 0 {
					t.Fatalf("evicted %v though too little could be freed", got)
				}
				sameSnapshot(t, before, e.snapshot(t))
			} else {
				must(t, err)
				want := []string{s.Entries[0].Digest, s.Entries[1].Digest}
				if got := rm.take(); !slices.Equal(got, want) {
					t.Fatalf("evicted %v, want %v", got, want)
				}
			}
			checkAccounting(t, c)
			assertIdle(t, c)
			for _, ls := range held {
				must(t, c.Release(ls))
			}
			must(t, c.Close())
		})
	}
}

// An entry evicted while Get is reading it is ErrNotFound, never a corrupt
// read; a leased entry is never evicted under the same pressure.
func TestEvictionDuringGet(t *testing.T) {
	lim, k := fitting(t)
	clk := newClock()
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{Limits: lim, CheckContent: noCheck, Now: clk.Now, wrapFS: withFault(&ffs)})
	var ds []string
	for i := 0; i < k; i++ {
		m, l := variant(t, i)
		en, err := c.Put(bg(), m, l)
		must(t, err)
		ds = append(ds, en.Digest)
		clk.tick()
	}
	victim := ds[0]
	var fired atomic.Bool
	var putErr error
	ffs.mu.Lock()
	ffs.hook = func(op, name string) error {
		if op == "open" && strings.HasSuffix(name, victim[7:]) && strings.HasPrefix(name, blobsDir) && fired.CompareAndSwap(false, true) {
			// Get has started reading the victim: admit another entry,
			// which evicts it (the least recently used, unleased).
			m, l := variant(t, 300)
			_, putErr = c.Put(bg(), m, l)
		}
		return nil
	}
	ffs.mu.Unlock()
	_, err := c.Get(bg(), victim)
	if !fired.Load() {
		t.Fatal("the race was not exercised")
	}
	must(t, putErr)
	if !errors.Is(err, ErrNotFound) || errors.Is(err, ErrCorrupt) {
		t.Fatalf("Get of an entry evicted mid-read: %v", err)
	}
	ffs.mu.Lock()
	ffs.hook = nil
	ffs.mu.Unlock()
	checkAccounting(t, c)
	assertIdle(t, c)

	// The same race on a leased entry: it is not evicted, Get succeeds.
	ents := c.Stats().Entries
	slices.SortFunc(ents, func(a, b EntryInfo) int {
		if x := a.LastUsed.Compare(b.LastUsed); x != 0 {
			return x
		}
		return strings.Compare(a.Digest, b.Digest)
	})
	oldest := ents[0].Digest
	ls, err := c.Acquire(oldest, bundle.HolderAssessment, "snapshot")
	must(t, err)
	var fired2 atomic.Bool
	ffs.mu.Lock()
	ffs.hook = func(op, name string) error {
		if op == "open" && strings.HasPrefix(name, blobsDir) && strings.HasSuffix(name, oldest[7:]) && fired2.CompareAndSwap(false, true) {
			m, l := variant(t, 301)
			_, putErr = c.Put(bg(), m, l)
		}
		return nil
	}
	ffs.mu.Unlock()
	if _, err := c.Get(bg(), oldest); err != nil {
		t.Fatalf("leased entry: %v", err)
	}
	if !fired2.Load() {
		t.Fatal("the race was not exercised")
	}
	must(t, putErr)
	must(t, c.Release(ls))
	checkAccounting(t, c)
}

// A leased entry found corrupt is removed, never served, and reported to its
// holders as ErrCorrupt (not as absent) until they release it or the
// verified bytes are stored again.
func TestCorruptWhileLeased(t *testing.T) {
	e := newEnv(t)
	var rm removals
	c := e.open(t, Config{CheckContent: noCheck, OnRemove: rm.add})
	a := small(t, 0)
	_, l1, err := c.PutLeased(bg(), a.Manifest, a.Layer, bundle.HolderApplied, "applied/a")
	must(t, err)
	l2, err := c.Acquire(a.ManifestDigest, bundle.HolderAssessment, "assessment/a")
	must(t, err)
	must(t, flipFile(filepath.Join(e.root, contentDir, a.ManifestDigest[7:], treeName, "LICENSE"), 0))
	for i := 0; i < 2; i++ {
		if _, err := c.Get(bg(), a.ManifestDigest); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("get %d: %v", i, err)
		}
	}
	if got := rm.take(); !slices.Equal(got, []string{a.ManifestDigest}) {
		t.Fatalf("removed %v", got)
	}
	if _, err := os.Lstat(filepath.Join(e.root, contentDir, a.ManifestDigest[7:])); !os.IsNotExist(err) {
		t.Fatalf("corrupt entry left: %v", err)
	}
	if _, err := c.Acquire(a.ManifestDigest, bundle.HolderProfile, "p"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new lease on a removed entry: %v", err)
	}
	checkAccounting(t, c)
	// Storing the verified bytes again restores it under the held leases.
	if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(bg(), a.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if s := c.Stats(); s.Leases != 2 || s.Entries[0].Leases != 2 {
		t.Fatalf("%+v", s)
	}
	// Corrupt again, release both: then it is simply absent.
	must(t, flipFile(filepath.Join(e.root, blobsDir, a.LayerDigest[7:]), 40))
	if _, err := c.Get(bg(), a.ManifestDigest); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	must(t, c.Release(l1))
	must(t, c.Release(l2))
	if _, err := c.Get(bg(), a.ManifestDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after release: %v", err)
	}
	checkAccounting(t, c)
	assertIdle(t, c)
}

// Concurrent Puts (evicting), leased Gets and releases: a leased entry is
// always served, an unleased one is served or absent but never corrupt, and
// the accounting is exact afterwards.
func TestEvictionStress(t *testing.T) {
	lim, k := fitting(t)
	e := newEnv(t)
	c := e.open(t, Config{Limits: lim, CheckContent: noCheck})
	const workers, rounds = 6, 12
	var wg sync.WaitGroup
	errc := make(chan error, workers*rounds*4)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				m, l := variant(t, (w*rounds+r)%(k+3))
				en, ls, err := c.PutLeased(bg(), m, l, bundle.HolderProfile, fmt.Sprint("w", w))
				if errors.Is(err, ErrCapacity) {
					continue // every entry leased by the other workers
				}
				if err != nil {
					errc <- err
					return
				}
				if _, err := c.Get(bg(), en.Digest); err != nil {
					errc <- fmt.Errorf("leased entry not served: %w", err)
				}
				// An unleased read of someone else's entry.
				m2, _ := variant(t, (w*rounds+r+1)%(k+3))
				if _, err := c.Get(bg(), digest(m2)); err != nil && !errors.Is(err, ErrNotFound) {
					errc <- fmt.Errorf("unleased read: %w", err)
				}
				if err := c.Release(ls); err != nil {
					errc <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	s := c.Stats()
	if s.Leases != 0 || s.UsedBytes > s.CapacityBytes {
		t.Fatalf("%+v", s)
	}
	checkAccounting(t, c)
	assertIdle(t, c)
	must(t, c.Close())
	c2 := e.open(t, Config{Limits: lim, CheckContent: noCheck})
	if c2.Stats().UsedBytes != s.UsedBytes {
		t.Fatalf("recount after reopen %d, was %d", c2.Stats().UsedBytes, s.UsedBytes)
	}
	checkAccounting(t, c2)
}
