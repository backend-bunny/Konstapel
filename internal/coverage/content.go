package coverage

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle"
)

// Content is a verified content handle: the declared OSCAL entry points,
// logical policies and file inventory of exactly one bundle digest, and its
// payload. Construct it with FromFrozen, FromDescriptor or FromVendored; the
// zero value reads nothing.
type Content struct {
	// Bundle is the pinned name and OCI manifest digest (for vendored
	// content, the sha256 of its SHA256SUMS) the handle serves.
	Bundle v1alpha1.BundleReference
	// OSCAL are the declared OSCAL entry points and their versions.
	OSCAL []bundle.OSCALDocument
	// Policies are the logical policies and their checks.
	Policies []bundle.Policy

	files   map[string]file
	payload fs.FS
}

type file struct {
	sha256 string // hex
	size   int64  // -1 when the inventory records none
}

// FromFrozen is the handle of a verified frozen bundle (bundle.ReadFrozen or
// the content owner's Freeze).
func FromFrozen(f *bundle.Frozen) (Content, error) {
	if f == nil || f.Descriptor == nil {
		return Content{}, errors.New("coverage: no frozen bundle")
	}
	return FromDescriptor(v1alpha1.BundleReference{Name: f.Identity.Name, Digest: f.Identity.Digests.OCI}, f.Descriptor, f.Payload)
}

// FromDescriptor is the handle of a verified descriptor and its payload, such
// as an integrity-checked cache entry (entry.Descriptor, entry.FS()). The
// caller vouches that payload was verified against d under ref.
func FromDescriptor(ref v1alpha1.BundleReference, d *bundle.Descriptor, payload fs.FS) (Content, error) {
	if d == nil || payload == nil {
		return Content{}, errors.New("coverage: a descriptor and payload are required")
	}
	if ref.Name != d.Name {
		return Content{}, fmt.Errorf("coverage: descriptor is %s, not %s", d.Name, ref.Name)
	}
	files := make(map[string]file, len(d.Files))
	for _, f := range d.Files {
		files[f.Path] = file{sha256: f.SHA256, size: f.Size}
	}
	return Content{Bundle: ref, OSCAL: d.OSCAL, Policies: d.Policies, files: files, payload: payload}, nil
}

// vendoredSums is the vendored tree's checksum list, relative to its root.
const vendoredSums = "content/SHA256SUMS"

// FromVendored is the handle of the image's vendored content tree at root
// (the parent of content/). Its digest is the sha256 of content/SHA256SUMS,
// as targeting.LocalContent defines it, and must equal ref.Digest: other
// content is never substituted. Only files SHA256SUMS lists are in the
// closure. oscal and policies declare the entry points and logical policies
// the caller serves under ref (normally the bundle definition's).
func FromVendored(root fs.FS, ref v1alpha1.BundleReference, oscal []bundle.OSCALDocument, policies []bundle.Policy) (Content, error) {
	sums, err := fs.ReadFile(root, vendoredSums)
	if err != nil {
		return Content{}, fmt.Errorf("coverage: vendored content: %w", err)
	}
	if got := digest(sums); got != ref.Digest {
		return Content{}, fmt.Errorf("coverage: vendored content is %s, not %s; other content is never substituted", got, ref.Digest)
	}
	files := map[string]file{}
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		sum, p, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 64 || !fs.ValidPath(p) {
			return Content{}, fmt.Errorf("coverage: malformed %s line %q", vendoredSums, sc.Text())
		}
		files[p] = file{sha256: sum, size: -1}
	}
	if err := sc.Err(); err != nil {
		return Content{}, err
	}
	return Content{Bundle: ref, OSCAL: oscal, Policies: policies, files: files, payload: root}, nil
}

// inClosure reports whether p is an inventoried file of the handle.
func (c Content) inClosure(p string) bool {
	_, ok := c.files[p]
	return ok
}

// read returns an inventoried file's bytes, re-checked against the
// inventory, and its "sha256:<hex>" digest.
func (c Content) read(p string) ([]byte, string, error) {
	f, ok := c.files[p]
	if !ok {
		return nil, "", fmt.Errorf("%s is not in the content's file inventory", p)
	}
	raw, err := fs.ReadFile(c.payload, p)
	if err != nil {
		return nil, "", err
	}
	d := digest(raw)
	if d != "sha256:"+f.sha256 || (f.size >= 0 && int64(len(raw)) != f.size) {
		return nil, "", fmt.Errorf("%s no longer matches its verified digest", p)
	}
	return raw, d, nil
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
