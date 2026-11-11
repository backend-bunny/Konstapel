package cache

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// fileSum is the size and SHA-256 of one archive file.
type fileSum struct {
	size   int64
	sha256 [sha256.Size]byte
}

// inventory is what a streaming pass over a layer found: every regular file
// with its size and digest, the directories its paths imply, and the bytes
// of bundle.json. It is derived from the layer alone, never from disk.
type inventory struct {
	files      map[string]fileSum
	dirs       []string // implied directories, sorted (parents first)
	unpacked   int64
	descriptor []byte
}

// createFunc opens a new file for an archive path during extraction.
type createFunc func(name string) (writer, error)

// scanLayer streams a tar+gzip layer and enforces the archive policy while
// it reads: limits on compressed bytes consumed, decompressed bytes, regular
// files, directories, path length and depth are checked before the bytes
// they govern are read or written. With create == nil it writes nothing;
// otherwise each accepted file is written through create exactly once,
// fsynced and closed before the next header is read. A violation stops the
// pass at once.
func scanLayer(r io.Reader, lim Limits, create createFunc) (*inventory, error) {
	// gzip reads from a ByteReader without buffering past the member, so
	// anything after it remains in br and is detected below.
	compressed := &limitReader{r: bufio.NewReader(r), max: lim.MaxCompressedBytes}
	zr, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, compressed.classify(fmt.Errorf("%w: gzip: %v", ErrMalformed, err))
	}
	zr.Multistream(false)
	streamMax := lim.MaxUnpackedBytes + int64(lim.MaxFiles+2)*metadataPerEntry
	plain := &limitReader{r: zr, max: streamMax}
	inv, err := scanTar(plain, lim, create)
	if err != nil {
		return nil, plain.classify(compressed.classify(err))
	}
	// Past the end-of-archive marker only zero padding may follow, and the
	// gzip member must end there with a valid checksum and length.
	if err := zeroTail(plain); err != nil {
		return nil, plain.classify(compressed.classify(err))
	}
	if err := zr.Close(); err != nil {
		return nil, fmt.Errorf("%w: gzip: %v", ErrMalformed, err)
	}
	var one [1]byte
	if n, err := compressed.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
		return nil, compressed.classify(fmt.Errorf("%w: data after the gzip stream (a second member or trailing bytes)", ErrMalformed))
	}
	return inv, nil
}

func zeroTail(r io.Reader) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return fmt.Errorf("%w: data after the end of the tar archive", ErrMalformed)
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}
	}
}

func scanTar(r io.Reader, lim Limits, create createFunc) (*inventory, error) {
	tr := tar.NewReader(r)
	inv := &inventory{files: map[string]fileSum{}}
	paths := newPathSet()
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar: %v", ErrMalformed, err)
		}
		if err := checkType(h); err != nil {
			return nil, err
		}
		name := h.Name
		if err := checkName(name, lim); err != nil {
			return nil, err
		}
		if len(inv.files) >= lim.MaxFiles {
			return nil, fmt.Errorf("%w: more than %d files", ErrLimit, lim.MaxFiles)
		}
		if err := paths.add(name, lim.MaxFiles); err != nil {
			return nil, err
		}
		if h.Size < 0 || h.Size > lim.MaxUnpackedBytes-inv.unpacked {
			return nil, fmt.Errorf("%w: %s: unpacked payload exceeds %d bytes", ErrLimit, name, lim.MaxUnpackedBytes)
		}
		isDescriptor := name == bundle.DescriptorPath
		if isDescriptor && h.Size > lim.MaxDescriptorBytes {
			return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrLimit, name, lim.MaxDescriptorBytes)
		}
		inv.unpacked += h.Size
		sum, data, err := copyEntry(tr, name, h.Size, isDescriptor, create)
		if err != nil {
			return nil, err
		}
		inv.files[name] = sum
		if isDescriptor {
			inv.descriptor = data
		}
	}
	inv.dirs = paths.sortedDirs()
	return inv, nil
}

// copyEntry hashes exactly size bytes of the current entry, keeps them when
// they are the descriptor, and writes them when extracting.
func copyEntry(tr io.Reader, name string, size int64, keep bool, create createFunc) (fileSum, []byte, error) {
	h := sha256.New()
	dst := []io.Writer{h}
	var kept *bytes.Buffer
	if keep {
		kept = bytes.NewBuffer(make([]byte, 0, size))
		dst = append(dst, kept)
	}
	var w writer
	if create != nil {
		var err error
		if w, err = create(name); err != nil {
			return fileSum{}, nil, err
		}
		dst = append(dst, w)
	}
	n, err := io.CopyN(io.MultiWriter(dst...), tr, size)
	if err == nil && w != nil {
		err = w.Sync()
	}
	if w != nil {
		if cerr := w.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		if n < size && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			return fileSum{}, nil, fmt.Errorf("%w: %s: entry shorter than its declared %d bytes", ErrMalformed, name, size)
		}
		return fileSum{}, nil, fmt.Errorf("%s: %w", name, err)
	}
	s := fileSum{size: n}
	copy(s.sha256[:], h.Sum(nil))
	var data []byte
	if kept != nil {
		data = kept.Bytes()
	}
	return s, data, nil
}

// checkType admits only regular files: links, devices, FIFOs, directory
// entries (directories are implied by file paths and created by the cache),
// sparse files and PAX global headers are rejected. tar cannot carry sockets.
func checkType(h *tar.Header) error {
	switch h.Typeflag {
	case tar.TypeReg:
		return nil
	case tar.TypeSymlink, tar.TypeLink:
		return fmt.Errorf("%w: %q is a link", ErrUnsafeEntry, h.Name)
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		return fmt.Errorf("%w: %q is a special file", ErrUnsafeEntry, h.Name)
	case tar.TypeDir:
		return fmt.Errorf("%w: %q is a directory entry; directories are implied by file paths", ErrUnsafeEntry, h.Name)
	default:
		return fmt.Errorf("%w: %q has unsupported entry type %q", ErrUnsafeEntry, h.Name, h.Typeflag)
	}
}

// checkName enforces the portable path policy: a clean relative slash path
// of printable ASCII (no backslash), in an allowed payload location, within
// the length and depth limits. Restricting to ASCII makes Unicode
// normalization collisions impossible by construction; case collisions are
// found by pathSet.
func checkName(name string, lim Limits) error {
	if len(name) > lim.MaxPathBytes {
		return fmt.Errorf("%w: path of %d bytes exceeds %d", ErrLimit, len(name), lim.MaxPathBytes)
	}
	for i := 0; i < len(name); i++ {
		if c := name[i]; c < 0x20 || c > 0x7e || c == '\\' {
			return fmt.Errorf("%w: %q: paths are printable ASCII without backslashes (byte 0x%02x)", ErrUnsafeEntry, name, c)
		}
	}
	if name == "" || path.IsAbs(name) || path.Clean(name) != name || !fs.ValidPath(name) {
		return fmt.Errorf("%w: %q is not a clean relative path", ErrUnsafeEntry, name)
	}
	parts := strings.Split(name, "/")
	if len(parts) > lim.MaxDepth {
		return fmt.Errorf("%w: %q is deeper than %d components", ErrLimit, name, lim.MaxDepth)
	}
	for _, p := range parts {
		if len(p) > lim.MaxNameBytes {
			return fmt.Errorf("%w: %q has a component longer than %d bytes", ErrLimit, name, lim.MaxNameBytes)
		}
	}
	if name != bundle.DescriptorPath {
		if err := bundle.ValidPayloadPath(name); err != nil {
			return fmt.Errorf("%w: %v", ErrUnsafeEntry, err)
		}
	}
	return nil
}

// pathSet detects every pair of paths that would collide on a
// case-insensitive filesystem: exact duplicates, case variants of a file or
// of any directory component, and a path used both as a file and as a
// directory. Keys are ASCII-lowercased; checkName already admitted only
// ASCII, so this is the complete fold.
type pathSet struct {
	files map[string]string // folded -> original
	dirs  map[string]string
}

func newPathSet() *pathSet {
	return &pathSet{files: map[string]string{}, dirs: map[string]string{}}
}

func (s *pathSet) add(name string, maxDirs int) error {
	fold := strings.ToLower(name)
	if prev, ok := s.files[fold]; ok {
		if prev == name {
			return fmt.Errorf("%w: duplicate path %q", ErrUnsafeEntry, name)
		}
		return fmt.Errorf("%w: %q and %q collide on a case-insensitive filesystem", ErrUnsafeEntry, prev, name)
	}
	if prev, ok := s.dirs[fold]; ok {
		return fmt.Errorf("%w: %q is a file and the directory of %q", ErrUnsafeEntry, name, prev)
	}
	var newDirs []string
	for i := strings.IndexByte(name, '/'); i >= 0; i = nextSlash(name, i) {
		dir, dirFold := name[:i], fold[:i]
		if prev, ok := s.files[dirFold]; ok {
			return fmt.Errorf("%w: %q is a file and the directory of %q", ErrUnsafeEntry, prev, name)
		}
		if prev, ok := s.dirs[dirFold]; ok {
			if prev != dir {
				return fmt.Errorf("%w: directories %q and %q collide on a case-insensitive filesystem", ErrUnsafeEntry, prev, dir)
			}
			continue
		}
		newDirs = append(newDirs, dir)
	}
	if len(s.dirs)+len(newDirs) > maxDirs {
		return fmt.Errorf("%w: more than %d directories", ErrLimit, maxDirs)
	}
	for _, d := range newDirs {
		s.dirs[strings.ToLower(d)] = d
	}
	s.files[fold] = name
	return nil
}

func nextSlash(s string, i int) int {
	j := strings.IndexByte(s[i+1:], '/')
	if j < 0 {
		return -1
	}
	return i + 1 + j
}

func (s *pathSet) sortedDirs() []string {
	out := make([]string, 0, len(s.dirs))
	for _, d := range s.dirs {
		out = append(out, d)
	}
	sort.Strings(out) // a parent sorts before its children
	return out
}

// checkInventory is the archive-level equivalent of
// Descriptor.VerifyPayload: bundle.json is present and valid, every
// inventoried file is in the archive with its exact size and digest, and
// the archive holds nothing else.
func checkInventory(inv *inventory) (*bundle.Descriptor, error) {
	if inv.descriptor == nil {
		return nil, fmt.Errorf("%w: archive has no %s", ErrInventory, bundle.DescriptorPath)
	}
	d, err := bundle.ParseDescriptor(inv.descriptor)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInventory, err)
	}
	var errs []error
	want := map[string]bool{bundle.DescriptorPath: true}
	for _, f := range d.Files {
		want[f.Path] = true
		got, ok := inv.files[f.Path]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("%s: inventoried but missing from the archive", f.Path))
		case got.size != f.Size:
			errs = append(errs, fmt.Errorf("%s: size %d does not match inventory %d", f.Path, got.size, f.Size))
		case fmt.Sprintf("%x", got.sha256) != f.SHA256:
			errs = append(errs, fmt.Errorf("%s: sha256 %x does not match inventory %s", f.Path, got.sha256, f.SHA256))
		}
	}
	var extra []string
	for p := range inv.files {
		if !want[p] {
			extra = append(extra, p)
		}
	}
	sort.Strings(extra)
	for _, p := range extra {
		errs = append(errs, fmt.Errorf("%s: present in the archive but not inventoried", p))
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInventory, err)
	}
	return d, nil
}

// limitReader counts bytes read and fails once more than max are requested.
// The flag survives wrapping by gzip/tar errors, so classify can restore the
// limit as the cause.
type limitReader struct {
	r        io.Reader
	n, max   int64
	exceeded bool
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.n >= l.max {
		if len(p) == 0 {
			return 0, nil
		}
		// Probe one byte: reading exactly max bytes is allowed.
		var one [1]byte
		n, err := l.r.Read(one[:])
		if n > 0 {
			l.exceeded = true
			return 0, fmt.Errorf("%w: stream exceeds %d bytes", ErrLimit, l.max)
		}
		return 0, err
	}
	if rest := l.max - l.n; int64(len(p)) > rest {
		p = p[:rest]
	}
	n, err := l.r.Read(p)
	l.n += int64(n)
	return n, err
}

// ReadByte lets gzip/flate read without their own buffering.
func (l *limitReader) ReadByte() (byte, error) {
	if br, ok := l.r.(io.ByteReader); ok && l.n < l.max {
		c, err := br.ReadByte()
		if err == nil {
			l.n++
		}
		return c, err
	}
	var b [1]byte
	n, err := l.Read(b[:])
	if n == 1 {
		return b[0], nil
	}
	if err == nil {
		err = io.ErrNoProgress
	}
	return 0, err
}

func (l *limitReader) classify(err error) error {
	if l.exceeded && !errors.Is(err, ErrLimit) {
		return fmt.Errorf("%w: stream exceeds %d bytes (%v)", ErrLimit, l.max, err)
	}
	return err
}
