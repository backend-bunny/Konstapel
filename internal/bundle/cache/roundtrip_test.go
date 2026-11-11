package cache

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// The official bundle round-trips: Put extracts exactly what the in-memory
// Unpack yields, with fixed modes, the default content check passes, and Get
// and the raw-byte accessors return the verified bytes.
func TestOfficialBundleRoundTrip(t *testing.T) {
	a := official(t)
	e := newEnv(t)
	c := e.open(t, Config{})
	got, err := c.Put(bg(), a.Manifest, a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != a.ManifestDigest || got.LayerDigest != a.LayerDigest || got.ContentDigest != a.Descriptor.ContentDigest() {
		t.Fatalf("identities: %+v", got)
	}
	if want := filepath.Join(e.root, "content", "sha256", a.ManifestDigest[7:], "tree"); got.Dir != want {
		t.Fatalf("dir %s, want %s", got.Dir, want)
	}
	_, mem, err := bundle.Unpack(a.Layer)
	if err != nil {
		t.Fatal(err)
	}
	disk := readTree(t, got.Dir)
	if len(disk) != len(mem) {
		t.Fatalf("%d files on disk, %d in memory", len(disk), len(mem))
	}
	for p, f := range mem {
		if !bytes.Equal(disk[p], f.Data) {
			t.Errorf("%s differs from Unpack", p)
		}
	}
	if err := got.Descriptor.VerifyPayload(got.FS()); err != nil {
		t.Fatal(err)
	}
	// Modes: files read-only, never executable or special; dirs not writable
	// by others; blobs and record likewise read-only.
	must(t, filepath.WalkDir(e.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		m := info.Mode()
		if m&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky|fs.ModeSymlink) != 0 {
			t.Errorf("%s: mode %v", p, m)
		}
		if m.IsRegular() && filepath.Base(p) != lockName && m.Perm()&^0o444 != 0 {
			t.Errorf("%s: file mode %v is writable or executable", p, m.Perm())
		}
		if m.IsDir() && m.Perm()&0o022 != 0 {
			t.Errorf("%s: dir mode %v", p, m.Perm())
		}
		return nil
	}))
	for _, check := range []struct {
		name string
		get  func() ([]byte, error)
		want []byte
	}{{"manifest", got.Manifest, a.Manifest}, {"layer", got.Layer, a.Layer}} {
		b, err := check.get()
		if err != nil || !bytes.Equal(b, check.want) {
			t.Errorf("%s: %v", check.name, err)
		}
	}
	again, err := c.Get(bg(), a.ManifestDigest)
	if err != nil || again.Dir != got.Dir || again.Bytes != got.Bytes {
		t.Fatalf("Get: %+v %v", again, err)
	}
	// A second Put of the same bytes reuses the entry.
	before := e.snapshot(t)
	if _, err := c.Put(bg(), a.Manifest, a.Layer); err != nil {
		t.Fatal(err)
	}
	sameSnapshot(t, before, e.snapshot(t))
	s := c.Stats()
	if len(s.Entries) != 1 || s.UsedBytes != got.Bytes || s.Entries[0].Bytes != got.Bytes {
		t.Fatalf("stats %+v, entry bytes %d", s, got.Bytes)
	}
	assertIdle(t, c)

	// After a restart the entry is recovered with the same charge.
	must(t, c.Close())
	c2 := e.open(t, Config{})
	if s2 := c2.Stats(); s2.UsedBytes != s.UsedBytes || len(s2.Entries) != 1 {
		t.Fatalf("after restart %+v, before %+v", s2, s)
	}
	if _, err := c2.Get(bg(), a.ManifestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Get(bg(), digest([]byte("other"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing digest: %v", err)
	}
}
