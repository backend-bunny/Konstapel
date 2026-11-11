package cache

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// patchSize rewrites the size field of the USTAR header at off and fixes its
// checksum, producing an entry whose declared size lies.
func patchSize(raw []byte, off int, size int64) []byte {
	out := append([]byte(nil), raw...)
	h := out[off : off+512]
	copy(h[124:136], fmt.Sprintf("%011o\x00", size))
	copy(h[148:156], "        ")
	var sum int64
	for _, b := range h {
		sum += int64(b)
	}
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return out
}

// paxNul writes a PAX path record containing NUL, which archive/tar's
// writer would refuse, by patching a same-length vendor record.
func paxNul(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	must(t, tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "content/a", Size: 1, Mode: 0o644, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"abcd": "content/aXb"}}))
	_, err := tw.Write([]byte("x"))
	must(t, err)
	must(t, tw.Close())
	raw := buf.Bytes()
	i := bytes.Index(raw, []byte("abcd=content/aXb"))
	if i < 0 {
		t.Fatal("record not found")
	}
	copy(raw[i:], "path=content/a\x00b")
	return raw
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

type archiveCase struct {
	name  string
	layer []byte // tar+gzip; the manifest is built for it unless manifest is set
	// manifest overrides the generated one.
	manifest []byte
	want     error
}

func unsafeArchiveCases(t testing.TB) []archiveCase {
	reg := func(name string) ent { return ent{name: name, body: []byte("x")} }
	pax := func(ents ...ent) []byte { return gz(t, mktar(t, tar.FormatPAX, ents...), 0) }
	ustar := func(ents ...ent) []byte { return gz(t, mktar(t, tar.FormatUSTAR, ents...), 0) }
	official := mktar(t, tar.FormatPAX, filesOf(t, small(t, 0))...)
	officialGz := gz(t, official, 0)
	oneFile := mktar(t, tar.FormatUSTAR, ent{name: "content/a", body: []byte("hello world")})
	longFile := mktar(t, tar.FormatUSTAR, ent{name: "content/a", body: bytes.Repeat([]byte("A"), 1500)})
	deep := strings.Repeat("d/", 32) + "f"
	var many []ent
	for i := 0; i <= 4096; i++ {
		many = append(many, ent{name: fmt.Sprintf("content/f%05d", i)})
	}
	random := make([]byte, 1<<10)
	rand.Read(random)

	cases := []archiveCase{
		// Traversal and unclean paths.
		{"parent", pax(reg("../x")), nil, ErrUnsafeEntry},
		{"parent of payload", pax(reg("content/../../unrelated/file")), nil, ErrUnsafeEntry},
		{"absolute", pax(reg("/etc/passwd")), nil, ErrUnsafeEntry},
		{"absolute payload", pax(reg("/content/a")), nil, ErrUnsafeEntry},
		{"dot prefix", pax(reg("./content/a")), nil, ErrUnsafeEntry},
		{"inner dot", pax(reg("content/./a")), nil, ErrUnsafeEntry},
		{"inner dotdot", pax(reg("content/x/../a")), nil, ErrUnsafeEntry},
		{"double slash", pax(reg("content//a")), nil, ErrUnsafeEntry},
		{"dotdot only", pax(reg("..")), nil, ErrUnsafeEntry},
		{"backslash", pax(reg(`content\..\..\x`)), nil, ErrUnsafeEntry},
		{"windows drive", pax(reg(`C:\x`)), nil, ErrUnsafeEntry},
		// A USTAR name ends at its first NUL, so only a PAX path can carry
		// one; the tar reader refuses it.
		{"nul in pax path", gz(t, paxNul(t), 0), nil, ErrMalformed},
		{"control byte", pax(reg("content/a\x01")), nil, ErrUnsafeEntry},
		{"delete byte", pax(reg("content/a\x7f")), nil, ErrUnsafeEntry},
		{"outside payload", pax(reg("etc/passwd")), nil, ErrUnsafeEntry},
		{"top-level file", pax(reg("README")), nil, ErrUnsafeEntry},
		{"staging-like path", pax(reg("staging/x")), nil, ErrUnsafeEntry},
		{"cache-like path", pax(reg("content/sha256/../../../blobs/x")), nil, ErrUnsafeEntry},
		// Unicode is rejected outright: no normalization collision is possible.
		{"non-ascii", pax(reg("content/caf\u00e9")), nil, ErrUnsafeEntry},
		{"nfc and nfd", pax(reg("content/caf\u00e9"), reg("content/cafe\u0301")), nil, ErrUnsafeEntry},
		{"kelvin sign", pax(reg("content/k"), reg("content/\u212a")), nil, ErrUnsafeEntry},
		{"invalid utf-8", pax(reg("content/\xff")), nil, ErrUnsafeEntry},
		// Duplicates and case-insensitive collisions.
		{"duplicate", pax(reg("content/a"), reg("content/a")), nil, ErrUnsafeEntry},
		{"case variant", pax(reg("content/A"), reg("content/a")), nil, ErrUnsafeEntry},
		{"case variant licenses", pax(reg("licenses/X"), reg("licenses/x")), nil, ErrUnsafeEntry},
		{"directory case variant", pax(reg("content/Dir/a"), reg("content/dir/b")), nil, ErrUnsafeEntry},
		{"file then directory", pax(reg("content/a"), reg("content/a/b")), nil, ErrUnsafeEntry},
		{"directory then file", pax(reg("content/a/b"), reg("content/a")), nil, ErrUnsafeEntry},
		{"file then case directory", pax(reg("content/a"), reg("content/A/b")), nil, ErrUnsafeEntry},
		{"duplicate descriptor", pax(reg("bundle.json"), reg("bundle.json")), nil, ErrUnsafeEntry},
		{"descriptor case variant", pax(reg("bundle.json"), reg("BUNDLE.JSON")), nil, ErrUnsafeEntry},
		// Links and special files.
		{"symlink out", pax(ent{name: "content/l", typ: tar.TypeSymlink, link: "../../unrelated/file"}), nil, ErrUnsafeEntry},
		{"symlink absolute", pax(ent{name: "content/l", typ: tar.TypeSymlink, link: "/etc/passwd"}), nil, ErrUnsafeEntry},
		{"symlink then write through", pax(ent{name: "content/l", typ: tar.TypeSymlink, link: "../.."}, reg("content/l/x")), nil, ErrUnsafeEntry},
		{"hardlink", pax(reg("LICENSE"), ent{name: "content/h", typ: tar.TypeLink, link: "LICENSE"}), nil, ErrUnsafeEntry},
		{"hardlink out", pax(ent{name: "content/h", typ: tar.TypeLink, link: "../unrelated/file"}), nil, ErrUnsafeEntry},
		{"char device", pax(ent{name: "content/c", typ: tar.TypeChar}), nil, ErrUnsafeEntry},
		{"block device", pax(ent{name: "content/b", typ: tar.TypeBlock}), nil, ErrUnsafeEntry},
		{"fifo", pax(ent{name: "content/f", typ: tar.TypeFifo}), nil, ErrUnsafeEntry},
		{"directory entry", pax(ent{name: "content/", typ: tar.TypeDir}), nil, ErrUnsafeEntry},
		{"contiguous file", pax(ent{name: "content/c", typ: tar.TypeCont}), nil, ErrUnsafeEntry},
		{"setuid file outside payload", pax(ent{name: "bin/x", body: []byte("x"), mode: 0o4755}), nil, ErrUnsafeEntry},
		// Names and counts.
		{"long component", pax(reg("content/" + strings.Repeat("a", 256))), nil, ErrLimit},
		{"long path", pax(reg("content/" + strings.Repeat("a/", 510) + "b")), nil, ErrLimit},
		{"deep path", pax(reg("content/" + deep)), nil, ErrLimit},
		{"too many files", pax(many...), nil, ErrLimit},
		// Malformed gzip and tar.
		{"not gzip", []byte("definitely not gzip"), nil, ErrMalformed},
		{"empty", nil, nil, ErrMalformed},
		{"gzip header only", officialGz[:10], nil, ErrMalformed},
		{"truncated half", officialGz[:len(officialGz)/2], nil, ErrMalformed},
		{"truncated trailer", officialGz[:len(officialGz)-4], nil, ErrMalformed},
		{"truncated last byte", officialGz[:len(officialGz)-1], nil, ErrMalformed},
		{"bad crc", flip(officialGz, len(officialGz)-6), nil, ErrMalformed},
		{"corrupt deflate", flip(officialGz, len(officialGz)/2), nil, ErrMalformed},
		{"trailing garbage", cat(officialGz, []byte("junk")), nil, ErrMalformed},
		{"trailing zero byte", cat(officialGz, []byte{0}), nil, ErrMalformed},
		{"second gzip member", cat(officialGz, gz(t, mktar(t, tar.FormatPAX, reg("content/evil")), 0)), nil, ErrMalformed},
		{"second empty gzip member", cat(officialGz, gz(t, nil, 0)), nil, ErrMalformed},
		{"data after tar end", gz(t, cat(official, []byte("junk")), 0), nil, ErrMalformed},
		{"second tar after end", gz(t, cat(official, mktar(t, tar.FormatPAX, reg("content/evil"))), 0), nil, ErrMalformed},
		{"truncated tar entry", gz(t, oneFile[:512+5], 0), nil, ErrMalformed},
		{"size lies larger", gz(t, patchSize(oneFile, 0, 4096), 0), nil, ErrMalformed},
		// The undeclared rest of the data runs into where the next header
		// must be.
		{"size lies smaller", gz(t, patchSize(longFile, 0, 2), 0), nil, ErrMalformed},
		{"negative size", gz(t, patchSize(oneFile, 0, -1), 0), nil, ErrMalformed},
		{"tar garbage", gz(t, random, 0), nil, ErrMalformed},
		// No descriptor at all.
		{"empty tar", ustar(), nil, ErrInventory},
		// Manifest/layer pairing.
		{"layer not named by manifest", officialGz, manifestFor(t, gz(t, official, 1), nil), ErrIntegrity},
		{"manifest is not a bundle manifest", officialGz, []byte(`{"schemaVersion":2}`), ErrMalformed},
		{"manifest not json", officialGz, []byte(`nope`), ErrMalformed},
		{"manifest too large", officialGz, bytes.Repeat([]byte(" "), 4<<20+1), ErrLimit},
	}
	return cases
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0xff
	return out
}

// Every unsafe or malformed archive is rejected with its class, and leaves
// the cache root (including an existing verified entry), a sibling
// directory and a symlink byte-for-byte unchanged, with no reservation or
// staging left behind.
func TestRejectsUnsafeArchives(t *testing.T) {
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
	m0, l0 := variant(t, 0)
	existing, err := c.Put(bg(), m0, l0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range unsafeArchiveCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			manifest := tc.manifest
			if manifest == nil {
				manifest = manifestFor(t, tc.layer, nil)
			}
			before := e.snapshot(t)
			ops := len(ffs.log())
			_, err := c.Put(bg(), manifest, tc.layer)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			sameSnapshot(t, before, e.snapshot(t))
			assertIdle(t, c)
			// The archive policy runs before anything is written.
			for _, op := range ffs.log()[ops:] {
				if !strings.HasPrefix(op, "lstat ") && !strings.HasPrefix(op, "open ") && !strings.HasPrefix(op, "readdir ") && !strings.HasPrefix(op, "close ") {
					t.Errorf("rejected archive caused %q", op)
				}
			}
			if _, err := c.Get(bg(), existing.Digest); err != nil {
				t.Fatalf("existing entry: %v", err)
			}
		})
	}
	if s := c.Stats(); len(s.Entries) != 1 {
		t.Fatalf("entries: %+v", s.Entries)
	}
}

// Decompression limits: both passes stop at the limit. Pass 1 alone rejects
// before any write; pass 2, run directly, never writes past the limit.
func TestDecompressionLimits(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxUnpackedBytes = 1 << 20
	lim.MaxDescriptorBytes = 64 << 10
	lim.MaxCompressedBytes = 256 << 10
	lim.MaxFiles = 8
	lim.CapacityBytes = lim.worstCaseReservation()
	zeros := func(n int) []byte { return make([]byte, n) }
	files := func(n, size int) []ent {
		var out []ent
		for i := 0; i < n; i++ {
			out = append(out, ent{name: fmt.Sprintf("content/f%d", i), body: zeros(size)})
		}
		return out
	}
	random := make([]byte, 300<<10)
	rand.Read(random)
	var deepDirs []ent
	for i := 0; i < 5; i++ {
		deepDirs = append(deepDirs, ent{name: fmt.Sprintf("content/a%d/b/c", i), body: []byte("x")})
	}
	cases := []struct {
		name  string
		layer []byte
		want  error
		// noWrite: rejected from its header, before any byte is written.
		noWrite bool
	}{
		{"one huge file", gz(t, mktar(t, tar.FormatPAX, ent{name: "content/z", body: zeros(8 << 20)}), 0), ErrLimit, true},
		{"sum of files", gz(t, mktar(t, tar.FormatPAX, files(4, 400<<10)...), 0), ErrLimit, false},
		{"exactly at limit then one byte", gz(t, mktar(t, tar.FormatPAX, append(files(1, 1<<20), ent{name: "content/y", body: []byte("x")})...), 0), ErrLimit, false},
		{"too many files", gz(t, mktar(t, tar.FormatPAX, files(9, 1)...), 0), ErrLimit, false},
		{"too many directories", gz(t, mktar(t, tar.FormatPAX, deepDirs...), 0), ErrLimit, false},
		{"descriptor too large", gz(t, mktar(t, tar.FormatPAX, ent{name: "bundle.json", body: zeros(65<<10 + 1)}), 0), ErrLimit, true},
		{"compressed too large", gz(t, mktar(t, tar.FormatPAX, ent{name: "content/r", body: random}), 0), ErrLimit, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Through Put: nothing is created at all.
			e := newEnv(t)
			var ffs *faultFS
			c := e.open(t, Config{Limits: lim, CheckContent: noCheck, wrapFS: withFault(&ffs)})
			before := e.snapshot(t)
			_, err := c.Put(bg(), manifestFor(t, tc.layer, nil), tc.layer)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Put: %v, want %v", err, tc.want)
			}
			sameSnapshot(t, before, e.snapshot(t))
			assertIdle(t, c)
			if ffs.written != 0 {
				t.Fatalf("Put wrote %d bytes", ffs.written)
			}
			// The extraction pass on its own stops at the limit.
			var written int64
			var created int64
			_, err = scanLayer(bytes.NewReader(tc.layer), lim, func(string) (writer, error) {
				created++
				return &countWriter{n: &written}, nil
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("scan: %v, want %v", err, tc.want)
			}
			if written > lim.MaxUnpackedBytes || created > int64(lim.MaxFiles) {
				t.Fatalf("extraction wrote %d bytes in %d files past the limits", written, created)
			}
			if tc.noWrite && (written != 0 || created != 0) {
				t.Fatalf("wrote %d bytes in %d files before rejecting", written, created)
			}
		})
	}
}

type countWriter struct{ n *int64 }

func (w *countWriter) Write(p []byte) (int, error) { *w.n += int64(len(p)); return len(p), nil }
func (w *countWriter) Sync() error                 { return nil }
func (w *countWriter) Close() error                { return nil }

// A compressed stream longer than the limit is cut off while reading, even
// when the caller did not check its length first (as on reuse).
func TestCompressedStreamLimit(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxCompressedBytes = 4 << 10
	random := make([]byte, 64<<10)
	rand.Read(random)
	layer := gz(t, mktar(t, tar.FormatPAX, ent{name: "content/r", body: random}), 0)
	r := &countingReader{r: bytes.NewReader(layer)}
	if _, err := scanLayer(r, lim, nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("got %v", err)
	}
	if r.n > lim.MaxCompressedBytes+int64(4096+1) { // bufio may read one buffer ahead
		t.Fatalf("read %d compressed bytes", r.n)
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Inventory mismatches between bundle.json and the archive are rejected
// before anything is written, leaving everything unchanged.
func TestInventoryMismatches(t *testing.T) {
	base := filesOf(t, small(t, 0))
	edit := func(f func([]ent) []ent) []byte {
		cp := make([]ent, len(base))
		for i, e := range base {
			cp[i] = ent{name: e.name, body: append([]byte(nil), e.body...)}
		}
		return gz(t, mktar(t, tar.FormatPAX, f(cp)...), 0)
	}
	find := func(es []ent, name string) int {
		for i, e := range es {
			if e.name == name {
				return i
			}
		}
		t.Fatalf("no %s", name)
		return -1
	}
	const victim = "content/provenance.json"
	cases := map[string][]byte{
		"missing file":         edit(func(es []ent) []ent { i := find(es, victim); return append(es[:i], es[i+1:]...) }),
		"extra file":           edit(func(es []ent) []ent { return append(es, ent{name: "content/extra.json", body: []byte("{}")}) }),
		"extra file elsewhere": edit(func(es []ent) []ent { return append(es, ent{name: "licenses/extra"}) }),
		"resized file":         edit(func(es []ent) []ent { i := find(es, victim); es[i].body = append(es[i].body, ' '); return es }),
		"retampered file": edit(func(es []ent) []ent {
			i := find(es, victim)
			es[i].body[0] ^= 0x01
			return es
		}),
		"bad digest in descriptor": edit(func(es []ent) []ent {
			i := find(es, "bundle.json")
			re := []byte(`"sha256": "`)
			j := bytes.Index(es[i].body, re) + len(re)
			if es[i].body[j] == '0' {
				es[i].body[j] = '1'
			} else {
				es[i].body[j] = '0'
			}
			return es
		}),
		"missing descriptor": edit(func(es []ent) []ent { i := find(es, "bundle.json"); return append(es[:i], es[i+1:]...) }),
		"invalid descriptor": edit(func(es []ent) []ent { i := find(es, "bundle.json"); es[i].body = []byte(`{"format":"x"}`); return es }),
		"descriptor trailing data": edit(func(es []ent) []ent {
			i := find(es, "bundle.json")
			es[i].body = append(es[i].body, []byte("{}")...)
			return es
		}),
	}
	e := newEnv(t)
	c := e.open(t, Config{CheckContent: noCheck})
	if _, err := c.Put(bg(), small(t, 1).Manifest, small(t, 1).Layer); err != nil {
		t.Fatal(err)
	}
	for name, layer := range cases {
		t.Run(name, func(t *testing.T) {
			before := e.snapshot(t)
			_, err := c.Put(bg(), manifestFor(t, layer, nil), layer)
			if !errors.Is(err, ErrInventory) {
				t.Fatalf("got %v", err)
			}
			sameSnapshot(t, before, e.snapshot(t))
			assertIdle(t, c)
		})
	}
}

// The on-disk verification is the equivalent of Descriptor.VerifyPayload:
// it catches what pass 1 cannot, a tree changed after extraction.
func TestExtractedTreeVerified(t *testing.T) {
	e := newEnv(t)
	var ffs *faultFS
	c := e.open(t, Config{CheckContent: noCheck, wrapFS: withFault(&ffs)})
	a := small(t, 0)
	// Tamper with a staged file between its close and verification.
	ffs.hook = func(op, name string) error {
		if op == "syncdir" && strings.HasSuffix(name, "/entry/tree") {
			ffs.hook = nil
			p := e.root + "/" + strings.TrimSuffix(name, "tree") + "tree/content/provenance.json"
			must(t, chmodWrite(p, []byte("tampered")))
		}
		return nil
	}
	before := e.snapshot(t)
	if _, err := c.Put(bg(), a.Manifest, a.Layer); !errors.Is(err, ErrInventory) {
		t.Fatalf("got %v", err)
	}
	sameSnapshot(t, before, e.snapshot(t))
	assertIdle(t, c)
}

// The content check gates promotion; its failure leaves nothing behind.
func TestContentCheckFailure(t *testing.T) {
	e := newEnv(t)
	boom := errors.New("boom")
	var seen string
	c := e.open(t, Config{CheckContent: func(_ *bundle.Descriptor, dir string) error { seen = dir; return boom }})
	before := e.snapshot(t)
	a := small(t, 0)
	if _, err := c.Put(bg(), a.Manifest, a.Layer); !errors.Is(err, ErrContent) || !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if !strings.HasPrefix(seen, e.root+"/staging/") {
		t.Fatalf("content check ran on %s", seen)
	}
	sameSnapshot(t, before, e.snapshot(t))
	assertIdle(t, c)
}

// chmodWrite replaces a read-only file's content in place.
func chmodWrite(p string, data []byte) error {
	if err := os.Chmod(p, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return err
	}
	return os.Chmod(p, 0o444)
}
