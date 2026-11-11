package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"

	"github.com/backend-bunny/Konstapel/internal/bundle"
)

const (
	// Modes the cache creates. Files are never writable or executable: the
	// payload is data that is read, never run. Umask can only remove bits.
	fileMode = 0o444
	dirMode  = 0o755
	// privateMode is for the cache root and staging directories.
	privateMode = 0o700
)

// recordFormat versions the integrity record.
const recordFormat = 1

// record is the integrity record stored beside each extracted tree. It is
// derived entirely from the verified bytes and contains no time, so it is
// identical for identical content and can be re-derived and compared byte
// for byte on reuse. It is a consistency check, never the trust anchor: the
// manifest digest in the entry's path is.
type record struct {
	Format   int     `json:"format"`
	Manifest blobRef `json:"manifest"`
	Layer    blobRef `json:"layer"`
	// Content is the canonical inventory digest (bundle.Descriptor.ContentDigest).
	Content string `json:"content"`
	// Descriptor is the sha256 digest of bundle.json as stored.
	Descriptor    string `json:"descriptor"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Files         int    `json:"files"`
	UnpackedBytes int64  `json:"unpackedBytes"`
}

type blobRef struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

func newRecord(manifest, layer blobRef, d *bundle.Descriptor, inv *inventory) ([]byte, error) {
	sum := inv.files[bundle.DescriptorPath].sha256
	return json.Marshal(record{
		Format: recordFormat, Manifest: manifest, Layer: layer,
		Content: d.ContentDigest(), Descriptor: "sha256:" + hex.EncodeToString(sum[:]),
		Name: d.Name, Version: d.Version, Files: len(inv.files), UnpackedBytes: inv.unpacked,
	})
}

// treeCost is the capacity charge of an extracted entry: every file and
// every directory (including the entry and tree directories) in whole blocks,
// plus the record.
func treeCost(inv *inventory, recordBytes int) int64 {
	cost := int64(len(inv.dirs)+2)*blockSize + blocks(int64(recordBytes))
	for _, f := range inv.files {
		cost += blocks(f.size)
	}
	return cost
}

// verifyTree checks the on-disk tree at dir against inv, which was derived
// from the authenticated layer: exactly the inventory's regular files with
// their sizes and digests, exactly the implied directories, no links or
// special files, and only the modes the cache creates. Every file is opened
// and then compared with its Lstat result, so a swap between the two is
// detected.
func verifyTree(fsys fileSystem, dir string, inv *inventory) error {
	wantDirs := map[string]bool{}
	for _, d := range inv.dirs {
		wantDirs[d] = true
	}
	seen := 0
	var walk func(rel string) error
	walk = func(rel string) error {
		entries, err := fsys.ReadDir(path.Join(dir, rel))
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := path.Join(rel, e.Name())
			full := path.Join(dir, p)
			info, err := fsys.Lstat(full)
			if err != nil {
				return err
			}
			mode := info.Mode()
			if mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
				return fmt.Errorf("%s: has a setuid, setgid or sticky bit", p)
			}
			switch {
			case mode.IsDir():
				if !wantDirs[p] {
					return fmt.Errorf("%s: unexpected directory", p)
				}
				if mode.Perm()&0o022 != 0 {
					return fmt.Errorf("%s: directory is group- or world-writable (%v)", p, mode.Perm())
				}
				delete(wantDirs, p)
				if err := walk(p); err != nil {
					return err
				}
			case mode.IsRegular():
				want, ok := inv.files[p]
				if !ok {
					return fmt.Errorf("%s: present on disk but not in the archive", p)
				}
				if seen++; seen > len(inv.files) {
					return errors.New("more files on disk than in the archive")
				}
				if mode.Perm()&^fileMode != 0 {
					return fmt.Errorf("%s: mode %v is writable or executable", p, mode.Perm())
				}
				if info.Size() != want.size {
					return fmt.Errorf("%s: size %d, want %d", p, info.Size(), want.size)
				}
				if err := checkFile(fsys, full, info, want); err != nil {
					return fmt.Errorf("%s: %w", p, err)
				}
			default:
				return fmt.Errorf("%s: not a regular file or directory (%v)", p, mode.Type())
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return err
	}
	if seen != len(inv.files) {
		var missing []string
		for p := range inv.files {
			if _, err := fsys.Lstat(path.Join(dir, p)); err != nil {
				missing = append(missing, p)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("missing from disk: %v", missing)
	}
	if len(wantDirs) != 0 {
		return fmt.Errorf("%d implied directories missing from disk", len(wantDirs))
	}
	return nil
}

func checkFile(fsys fileSystem, name string, lst fs.FileInfo, want fileSum) error {
	f, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(lst, st) || !st.Mode().IsRegular() {
		return errors.New("changed while being opened")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, want.size+1))
	if err != nil {
		return err
	}
	if n != want.size || [sha256.Size]byte(h.Sum(nil)) != want.sha256 {
		return errors.New("content does not match the archive")
	}
	return nil
}

// readBounded reads a regular file of at most max bytes.
func readBounded(fsys fileSystem, name string, max int64) ([]byte, error) {
	info, err := fsys.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s: %d bytes exceeds %d", name, info.Size(), max)
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, st) {
		return nil, fmt.Errorf("%s: changed while being opened", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: exceeds %d bytes", name, max)
	}
	return data, nil
}

// writeFile creates name, writes data, and fsyncs and closes it.
func writeFile(fsys fileSystem, name string, data []byte) error {
	w, err := fsys.Create(name, fileMode)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	if err == nil {
		err = w.Sync()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return err
}
