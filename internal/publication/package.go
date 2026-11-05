package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// LoadDescriptor reads and validates a package's descriptor.
func LoadDescriptor(dir string) (Descriptor, error) {
	var d Descriptor
	b, err := os.ReadFile(filepath.Join(dir, DescriptorFile))
	if err != nil {
		return d, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&d); err != nil {
		return d, fmt.Errorf("descriptor: %w", err)
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
