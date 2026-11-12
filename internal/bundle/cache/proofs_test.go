package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/bundle"
	"github.com/backend-bunny/Konstapel/internal/bundle/internal/provfixture"
	"github.com/backend-bunny/Konstapel/internal/bundle/verify"
)

var (
	fixOnce sync.Once
	fix     *provfixture.Fixtures
	fixRB   [2]*verify.RecheckBundle // the same evidence verified at two times
	fixErr  error
)

// fixture is the official bundle with organization-key proofs, and its
// verified recheck material.
func fixture(t testing.TB) (*provfixture.Fixtures, *verify.RecheckBundle, *verify.RecheckBundle) {
	t.Helper()
	fixOnce.Do(func() {
		if fix, fixErr = provfixture.Load(); fixErr != nil {
			return
		}
		for i := range fixRB {
			at := time.Date(2026, 11, 11, 12, i, 0, 0, time.UTC)
			v, err := verify.New(fix.Reader(), verify.WithClock(func() time.Time { return at }))
			if err != nil {
				fixErr = err
				return
			}
			acc, err := v.Accept(context.Background(), fix.Source(), fix.Result("sign-org", "prov-valid"))
			if err != nil {
				fixErr = err
				return
			}
			fixRB[i] = acc.Recheck
		}
	})
	if fixErr != nil {
		t.Fatal(fixErr)
	}
	return fix, fixRB[0], fixRB[1]
}

func encoded(t testing.TB, rb *verify.RecheckBundle) []byte {
	t.Helper()
	b, err := rb.Encode()
	must(t, err)
	return b
}

func proofPath(root, digest string) string { return filepath.Join(root, proofsDir, digest[7:]) }

func TestProofsRoundTrip(t *testing.T) {
	f, rb, rb2 := fixture(t)
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	if err := c.PutProofs(bg(), f.Subject, rb); !errors.Is(err, ErrNotFound) {
		t.Fatalf("proofs without an entry: %v", err)
	}
	if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Proofs(f.Subject); !errors.Is(err, ErrNoProofs) {
		t.Fatalf("no proofs yet: %v", err)
	}
	must(t, c.PutProofs(bg(), f.Subject, rb))
	got, err := c.Proofs(f.Subject)
	must(t, err)
	if !bytes.Equal(encoded(t, got), encoded(t, rb)) {
		t.Fatal("material changed in storage")
	}
	s := c.Stats()
	if s.Entries[0].ProofBytes != blocks(int64(proofHeaderLen+len(encoded(t, rb)))) {
		t.Fatalf("proof charge %d", s.Entries[0].ProofBytes)
	}
	checkAccounting(t, c)
	// Replacement is atomic and re-charged.
	must(t, c.PutProofs(bg(), f.Subject, rb2))
	got, err = c.Proofs(f.Subject)
	must(t, err)
	if !bytes.Equal(encoded(t, got), encoded(t, rb2)) {
		t.Fatal("not replaced")
	}
	checkAccounting(t, c)
	assertIdle(t, c)
	// It survives a restart and is charged again.
	used := c.Stats().UsedBytes
	must(t, c.Close())
	c = e.open(t, Config{CheckContent: noCheck})
	if c.Stats().UsedBytes != used {
		t.Fatalf("used %d after reopen, was %d", c.Stats().UsedBytes, used)
	}
	got, err = c.Proofs(f.Subject)
	must(t, err)
	if !bytes.Equal(encoded(t, got), encoded(t, rb2)) {
		t.Fatal("not restored")
	}
	checkAccounting(t, c)
}

// Invalid material is refused before anything is written.
func TestPutProofsRejects(t *testing.T) {
	f, rb, _ := fixture(t)
	e := newEnv(t)
	var ffs *faultFS
	lim := DefaultLimits()
	lim.MaxProofBytes = 4 << 10
	c := e.open(t, Config{CheckContent: noCheck, Limits: lim, wrapFS: withFault(&ffs)})
	a := small(t, 0)
	for _, b := range [][2][]byte{{f.Manifest, f.Layer}, {a.Manifest, a.Layer}} {
		if _, err := c.Put(bg(), b[0], b[1]); err != nil {
			t.Fatal(err)
		}
	}
	tampered := *rb
	tampered.Attestation.Bundle = append(bytes.Clone(rb.Attestation.Bundle), ' ')
	before := e.snapshot(t)
	ops := len(ffs.log())
	for name, c2 := range map[string]struct {
		digest string
		rb     *verify.RecheckBundle
		want   error
	}{
		"nil":             {f.Subject, nil, ErrProofs},
		"another subject": {a.ManifestDigest, rb, ErrProofs},
		"tampered":        {f.Subject, &tampered, ErrProofs},
		"over the limit":  {f.Subject, rb, ErrLimit},
		"bad digest":      {"sha256:abc", rb, ErrIntegrity},
	} {
		if err := c.PutProofs(bg(), c2.digest, c2.rb); !errors.Is(err, c2.want) {
			t.Errorf("%s: %v, want %v", name, err, c2.want)
		}
	}
	for _, op := range ffs.log()[ops:] {
		if !strings.HasPrefix(op, "lstat ") && !strings.HasPrefix(op, "open ") && !strings.HasPrefix(op, "readdir ") {
			t.Errorf("refused PutProofs performed %q", op)
		}
	}
	sameSnapshot(t, before, e.snapshot(t))
	assertIdle(t, c)
}

// Corrupted retained material is detected on reuse, removed and never
// returned; the entry itself stays. With a restart, Open's structural check
// may remove it first.
func TestProofsCorruption(t *testing.T) {
	f, rb, rb2 := fixture(t)
	other := encoded(t, rb2)
	otherFile, _ := proofFile(other)
	type outcome int
	const (
		corrupt outcome = iota // ErrCorrupt on read, then ErrNoProofs
		gone                   // removed at Open: ErrNoProofs, reported
		absent                 // nothing left to find: ErrNoProofs
		served                 // intact material for the subject: served
	)
	cases := map[string]struct {
		edit      func(t *testing.T, p string)
		restarted outcome
	}{
		"data byte":    {func(t *testing.T, p string) { must(t, flipFile(p, int64(proofHeaderLen+100))) }, corrupt},
		"header hash":  {func(t *testing.T, p string) { must(t, flipFile(p, int64(len(proofMagic)+3))) }, corrupt},
		"header magic": {func(t *testing.T, p string) { must(t, flipFile(p, 2)) }, gone},
		"truncated":    {func(t *testing.T, p string) { must(t, os.Chmod(p, 0o644)); must(t, os.Truncate(p, 50)) }, gone},
		"truncated end": {func(t *testing.T, p string) {
			must(t, os.Chmod(p, 0o644))
			must(t, os.Truncate(p, int64(proofHeaderLen+200)))
		}, corrupt},
		"appended": {func(t *testing.T, p string) {
			must(t, os.Chmod(p, 0o644))
			fh, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
			must(t, err)
			_, err = fh.Write([]byte(" "))
			must(t, err)
			must(t, fh.Close())
		}, corrupt},
		"deleted": {func(t *testing.T, p string) { must(t, os.Remove(p)) }, absent},
		"symlink": {func(t *testing.T, p string) { must(t, os.Remove(p)); must(t, os.Symlink("/etc/passwd", p)) }, gone},
		// A consistent file holding other valid material for the subject:
		// the in-memory hash detects the swap; after a restart only the
		// header remains, and the material is intact evidence that Recheck
		// judges under current trust like any other.
		"swapped for other valid material": {func(t *testing.T, p string) {
			must(t, os.Remove(p))
			must(t, os.WriteFile(p, otherFile, 0o444))
		}, served},
	}
	for name, tc := range cases {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%v", name, restart), func(t *testing.T) {
				e := newEnv(t)
				c := e.open(t, Config{CheckContent: noCheck})
				if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
					t.Fatal(err)
				}
				must(t, c.PutProofs(bg(), f.Subject, rb))
				tc.edit(t, proofPath(e.root, f.Subject))
				want := corrupt
				if restart {
					must(t, c.Close())
					c = e.open(t, Config{CheckContent: noCheck})
					want = tc.restarted
				}
				got, err := c.Proofs(f.Subject)
				switch want {
				case corrupt:
					if !errors.Is(err, ErrCorrupt) || got != nil {
						t.Fatalf("got %v", err)
					}
					if _, err := c.Proofs(f.Subject); !errors.Is(err, ErrNoProofs) {
						t.Fatalf("after removal: %v", err)
					}
				case gone:
					if !errors.Is(err, ErrNoProofs) || !contains(c.Recovery().Proofs, f.Subject[7:]) {
						t.Fatalf("got %v, recovery %+v", err, c.Recovery())
					}
				case absent:
					if !errors.Is(err, ErrNoProofs) {
						t.Fatalf("got %v", err)
					}
				case served:
					must(t, err)
					if !bytes.Equal(encoded(t, got), other) {
						t.Fatal("served other bytes")
					}
					return
				}
				if _, err := os.Lstat(proofPath(e.root, f.Subject)); !os.IsNotExist(err) {
					t.Fatalf("corrupt material left: %v", err)
				}
				if _, err := c.Get(bg(), f.Subject); err != nil {
					t.Fatalf("entry: %v", err)
				}
				checkAccounting(t, c)
				// Storing verified material again restores it.
				must(t, c.PutProofs(bg(), f.Subject, rb))
				if _, err := c.Proofs(f.Subject); err != nil {
					t.Fatal(err)
				}
				checkAccounting(t, c)
				assertIdle(t, c)
			})
		}
	}
}

// Proof material is reserved before it is written: when it does not fit
// and nothing but its own entry could be evicted, PutProofs fails with
// ErrCapacity having written and evicted nothing. It never evicts its own
// entry, but does evict other unleased entries.
func TestProofsCapacity(t *testing.T) {
	f, rb, _ := fixture(t)
	need := blocks(int64(proofHeaderLen + len(encoded(t, rb))))
	for _, leased := range []bool{true, false} {
		t.Run(fmt.Sprint("leased=", leased), func(t *testing.T) {
			e := newEnv(t)
			var ffs *faultFS
			var rm removals
			c := e.open(t, Config{CheckContent: noCheck, OnRemove: rm.add, wrapFS: withFault(&ffs)})
			if leased {
				_, _, err := c.PutLeased(bg(), f.Manifest, f.Layer, bundle.HolderProfile, "p")
				must(t, err)
			} else if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
				t.Fatal(err)
			}
			// An in-flight reservation takes all room but need-1 bytes.
			s := c.Stats()
			hold := s.CapacityBytes - s.UsedBytes - need + 1
			must(t, c.reserve(hold, ""))
			before := e.snapshot(t)
			ops := len(ffs.log())
			if err := c.PutProofs(bg(), f.Subject, rb); !errors.Is(err, ErrCapacity) {
				t.Fatalf("got %v", err)
			}
			for _, op := range ffs.log()[ops:] {
				if !strings.HasPrefix(op, "lstat ") && !strings.HasPrefix(op, "open ") && !strings.HasPrefix(op, "readdir ") {
					t.Errorf("refused PutProofs performed %q", op)
				}
			}
			sameSnapshot(t, before, e.snapshot(t))
			if got := rm.take(); len(got) != 0 {
				t.Fatalf("evicted %v", got)
			}
			c.release(hold)
			// An unleased other entry, then the same pressure: it is evicted.
			a := small(t, 0)
			if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
				t.Fatal(err)
			}
			c.mu.Lock()
			c.entries[f.Subject[7:]].lastUsed = c.entries[a.ManifestDigest[7:]].lastUsed.Add(time.Hour) // the fixture is newer
			c.mu.Unlock()
			s = c.Stats()
			hold = s.CapacityBytes - s.UsedBytes - need + 1
			must(t, c.reserve(hold, ""))
			must(t, c.PutProofs(bg(), f.Subject, rb))
			c.release(hold)
			if got := rm.take(); len(got) != 1 || got[0] != a.ManifestDigest {
				t.Fatalf("evicted %v", got)
			}
			if _, err := c.Proofs(f.Subject); err != nil {
				t.Fatal(err)
			}
			checkAccounting(t, c)
			assertIdle(t, c)
		})
	}
}

// Material goes with its entry, whichever way the entry is removed, and
// Open removes material whose entry is gone.
func TestProofsRemovedWithEntry(t *testing.T) {
	f, rb, _ := fixture(t)
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
		t.Fatal(err)
	}
	must(t, c.PutProofs(bg(), f.Subject, rb))
	// Corrupt the entry: quarantine removes the material too.
	must(t, flipFile(filepath.Join(e.root, blobsDir, f.Subject[7:]), 3))
	if _, err := c.Get(bg(), f.Subject); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(proofPath(e.root, f.Subject)); !os.IsNotExist(err) {
		t.Fatalf("material outlived its entry: %v", err)
	}
	checkAccounting(t, c)
	// Evict it: the material goes too.
	if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
		t.Fatal(err)
	}
	must(t, c.PutProofs(bg(), f.Subject, rb))
	s := c.Stats()
	must(t, c.reserve(s.CapacityBytes-s.UsedBytes+1, "")) // forces eviction of the only entry
	if _, err := os.Lstat(proofPath(e.root, f.Subject)); !os.IsNotExist(err) {
		t.Fatalf("material outlived eviction: %v", err)
	}
	c.release(s.CapacityBytes - s.UsedBytes + 1)
	checkAccounting(t, c)
	// Orphan material and stray names are removed at Open.
	if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
		t.Fatal(err)
	}
	must(t, c.PutProofs(bg(), f.Subject, rb))
	must(t, c.Close())
	orphan := strings.Repeat("d", 64)
	must(t, os.WriteFile(filepath.Join(e.root, proofsDir, orphan), []byte("x"), 0o444))
	must(t, os.WriteFile(filepath.Join(e.root, proofsDir, "junk"), []byte("x"), 0o444))
	c = e.open(t, Config{CheckContent: noCheck})
	r := c.Recovery()
	if !contains(r.Proofs, orphan) || !contains(r.Other, proofsDir+"/junk") || contains(r.Proofs, f.Subject[7:]) {
		t.Fatalf("recovery %+v", r)
	}
	if _, err := c.Proofs(f.Subject); err != nil {
		t.Fatal(err)
	}
	checkAccounting(t, c)
}

// A crash at every mutating step of PutProofs leaves the previous material
// or the new one, never a corrupt or uncharged file.
func TestProofsInterrupted(t *testing.T) {
	f, rb, rb2 := fixture(t)
	for k := 1; ; k++ {
		e := newEnv(t)
		var ffs *faultFS
		c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
		if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
			t.Fatal(err)
		}
		must(t, c.PutProofs(bg(), f.Subject, rb))
		ffs.mu.Lock()
		ffs.crashAt = ffs.mutates + k
		ffs.mu.Unlock()
		err := c.PutProofs(bg(), f.Subject, rb2)
		ffs.mu.Lock()
		crashed := ffs.crashed
		ffs.mu.Unlock()
		c.Close()
		c2 := e.open(t, Config{CheckContent: noCheck})
		got, gerr := c2.Proofs(f.Subject)
		must(t, gerr)
		g := encoded(t, got)
		if !bytes.Equal(g, encoded(t, rb)) && !bytes.Equal(g, encoded(t, rb2)) {
			t.Fatalf("step %d: other material", k)
		}
		if err == nil && !crashed && !bytes.Equal(g, encoded(t, rb2)) {
			t.Fatalf("step %d: completed but not durable", k)
		}
		checkAccounting(t, c2)
		assertIdle(t, c2)
		c2.Close()
		if !crashed {
			if k < 2 {
				t.Fatal("no step was interrupted")
			}
			return
		}
	}
}

// ENOSPC while writing material returns ErrNoSpace and leaves the previous
// material, the entry and the accounting unchanged.
func TestProofsDiskExhaustion(t *testing.T) {
	f, rb, rb2 := fixture(t)
	size := int64(proofHeaderLen + len(encoded(t, rb2)))
	for _, quota := range []int64{0, 1, size / 2, size - 1} {
		t.Run(fmt.Sprint(quota), func(t *testing.T) {
			e := newEnv(t)
			var ffs *faultFS
			c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
			if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
				t.Fatal(err)
			}
			must(t, c.PutProofs(bg(), f.Subject, rb))
			used := c.Stats().UsedBytes
			ffs.mu.Lock()
			ffs.quota, ffs.written = quota, 0
			ffs.mu.Unlock()
			if err := c.PutProofs(bg(), f.Subject, rb2); !errors.Is(err, ErrNoSpace) {
				t.Fatalf("got %v", err)
			}
			ffs.mu.Lock()
			ffs.quota = -1
			ffs.mu.Unlock()
			got, err := c.Proofs(f.Subject)
			must(t, err)
			if !bytes.Equal(encoded(t, got), encoded(t, rb)) {
				t.Fatal("previous material changed")
			}
			if c.Stats().UsedBytes != used {
				t.Fatalf("used %d, was %d", c.Stats().UsedBytes, used)
			}
			checkAccounting(t, c)
			assertIdle(t, c)
		})
	}
}

// Concurrent replacements leave exactly one complete material, charged once.
func TestProofsConcurrentReplace(t *testing.T) {
	f, rb, rb2 := fixture(t)
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	if _, err := c.Put(bg(), f.Manifest, f.Layer); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := rb
			if i%2 == 1 {
				m = rb2
			}
			if errs[i] = c.PutProofs(bg(), f.Subject, m); errs[i] == nil {
				_, errs[i] = c.Proofs(f.Subject)
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		must(t, err)
	}
	got, err := c.Proofs(f.Subject)
	must(t, err)
	if g := encoded(t, got); !bytes.Equal(g, encoded(t, rb)) && !bytes.Equal(g, encoded(t, rb2)) {
		t.Fatal("mixed material")
	}
	checkAccounting(t, c)
	assertIdle(t, c)
}
