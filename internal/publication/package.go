package publication

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// LoadDescriptor reads and validates a package's descriptor.
func LoadDescriptor(dir string) (Descriptor, error) {
	b, err := os.ReadFile(filepath.Join(dir, DescriptorFile))
	if err != nil {
		return Descriptor{}, err
	}
	return ParseDescriptor(b)
}

// maxDescriptorBytes bounds a descriptor read from an archive.
const maxDescriptorBytes = 16 << 20

// ArchiveDescriptor returns the descriptor bytes of a package archive (a
// gzip-compressed tar with the package's files at their package paths),
// such as a verified download. A missing, repeated or oversized descriptor
// fails.
func ArchiveDescriptor(r io.Reader) ([]byte, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("package archive: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var raw []byte
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("package archive: %w", err)
		}
		if h.Name != DescriptorFile {
			continue
		}
		if raw != nil {
			return nil, errors.New("package archive: the descriptor is repeated")
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxDescriptorBytes {
			return nil, errors.New("package archive: the descriptor is not a bounded regular file")
		}
		if raw, err = io.ReadAll(io.LimitReader(tr, maxDescriptorBytes+1)); err != nil {
			return nil, fmt.Errorf("package archive: %w", err)
		}
	}
	if raw == nil {
		return nil, errors.New("package archive: no descriptor")
	}
	return raw, nil
}

// PackageProtection reports whether the package of descriptor bytes raw is
// protected, so serving it requires document-read authority. A descriptor
// that names a protection marker, a protected role or a supporting-evidence
// path must validate fully, with a protection version this reader knows;
// anything else fails (fail closed): a reader that cannot tell what access
// a package requires must not serve it. An unprotected descriptor is only
// decoded, so packages produced under earlier rules stay readable.
func PackageProtection(raw []byte) (bool, error) {
	var loose struct {
		Protection json.RawMessage `json:"protection"`
		Files      []struct {
			Path string   `json:"path"`
			Role FileRole `json:"role"`
		} `json:"files"`
	}
	if err := json.Unmarshal(raw, &loose); err != nil {
		return false, fmt.Errorf("descriptor: %w", err)
	}
	marked := len(loose.Protection) > 0 && string(loose.Protection) != "null"
	for _, f := range loose.Files {
		if slices.Contains(ProtectedRoles, f.Role) || strings.HasPrefix(f.Path, SupportingDir) {
			marked = true
		}
	}
	if !marked {
		return false, nil
	}
	d, err := ParseDescriptor(raw)
	if err != nil {
		return false, err
	}
	if !d.Protected() {
		return false, errors.New("descriptor: protected files without a protection marker")
	}
	return true, nil
}

// ParseDescriptor decodes a descriptor strictly (unknown fields fail) and
// validates it.
func ParseDescriptor(b []byte) (Descriptor, error) {
	var d Descriptor
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, fmt.Errorf("descriptor: %w", err)
	}
	if dec.More() {
		return d, errors.New("descriptor: trailing data")
	}
	return d, d.Validate()
}

// VerifyDir checks that dir contains exactly the descriptor and its
// inventoried regular files with matching sizes and checksums. Symlinks,
// special files, and uninventoried files are rejected.
func VerifyDir(dir string, d Descriptor) error {
	if err := d.Validate(); err != nil {
		return err
	}
	want := map[string]File{}
	for _, f := range d.Files {
		want[f.Path] = f
	}
	var errs []error
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if e.IsDir() {
			return nil
		}
		if !e.Type().IsRegular() {
			errs = append(errs, fmt.Errorf("non-regular file %q", rel))
			return nil
		}
		if rel == DescriptorFile {
			return nil
		}
		f, ok := want[rel]
		if !ok {
			errs = append(errs, fmt.Errorf("uninventoried file %q", rel))
			return nil
		}
		delete(want, rel)
		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		if sum != f.SHA256 || size != f.Size {
			errs = append(errs, fmt.Errorf("checksum or size mismatch for %q", rel))
		}
		return nil
	})
	if err != nil {
		return err
	}
	missing := make([]string, 0, len(want))
	for p := range want {
		missing = append(missing, p)
	}
	sort.Strings(missing)
	for _, p := range missing {
		errs = append(errs, fmt.Errorf("missing file %q", p))
	}
	return errors.Join(errs...)
}

// Inventory lists a directory's files (excluding the descriptor) sorted by
// path, assigning roles with the supplied function. Producers use it when
// freezing a package; it rejects symlinks and special files.
func Inventory(dir string, role func(path string) FileRole) ([]File, error) {
	var files []File
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if !e.Type().IsRegular() {
			return fmt.Errorf("non-regular file %q", rel)
		}
		if rel == DescriptorFile {
			return nil
		}
		sum, size, err := hashFile(p)
		if err != nil {
			return err
		}
		files = append(files, File{Path: rel, Role: role(rel), SHA256: sum, Size: size})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, err
}

func hashFile(p string) (string, int64, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), int64(len(b)), nil
}

// Archive builds a deterministic gzip-compressed tar of a validated package
// directory: entries in path order with fixed modes, owners, and times, and
// no symlinks or special files. The same package yields the same bytes.
func Archive(dir string) ([]byte, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if !e.Type().IsRegular() {
			return fmt.Errorf("non-regular file %s", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("path %s escapes the package", path)
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.ModTime = time.Time{}
	tw := tar.NewWriter(zw)
	for _, rel := range paths {
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o644, Size: int64(len(b)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Extract writes the files of a package archive to dir (test and offline
// verification helper): regular files only, at clean relative paths. It
// verifies nothing else; LoadDescriptor and VerifyDir do.
func Extract(archive io.Reader, dir string) error {
	zr, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || safePath(h.Name) != nil && h.Name != DescriptorFile {
			return fmt.Errorf("package archive: unsafe entry %q", h.Name)
		}
		p := filepath.Join(dir, filepath.FromSlash(h.Name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, tr)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
}
