package bundle

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
	"path"
	"sort"
	"strings"
	"testing/fstest"
	"time"
)

// Limits bound what Unpack will read from an untrusted archive.
const (
	MaxFiles        = 4096
	MaxPayloadBytes = 256 << 20
)

// maxPayloadBytes is MaxPayloadBytes; tests lower it to avoid huge fixtures.
var maxPayloadBytes int64 = MaxPayloadBytes

// Include selects one repository file into the archive. The builder computes
// size and digest; the author supplies only where it comes from, where it goes
// and what it is.
type Include struct {
	// From is a slash-separated path relative to the source root.
	From string `json:"from"`
	// To is the archive path (see validPayloadPath).
	To   string `json:"to"`
	Role string `json:"role"`
}

// Definition is the build input: everything in bundle.json except the file
// inventory, plus the files to include. Composition happens here, at build
// time, by reference to existing sources; nothing is copied into the
// repository and no rule identity is invented.
type Definition struct {
	Name          string          `json:"name"`
	Version       string          `json:"version"`
	Source        Source          `json:"source"`
	Policies      []Policy        `json:"policies"`
	Scope         Scope           `json:"scope"`
	Compatibility Compatibility   `json:"compatibility"`
	OSCAL         []OSCALDocument `json:"oscal"`
	Include       []Include       `json:"include"`
}

// Archive is a frozen, content-addressed bundle ready to publish.
type Archive struct {
	Descriptor *Descriptor
	// Layer is the deterministic tar+gzip bytes and its digest.
	Layer       []byte
	LayerDigest string
	// Manifest is the OCI image manifest bytes and its digest.
	Manifest       []byte
	ManifestDigest string
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Build constructs the archive and manifest from def, reading sources from
// root. Identical definition, source bytes and timestamp always produce
// identical digests: paths are sorted, ownership and modes are fixed, entry
// times are the source commit time, JSON is stable and the gzip header carries
// no name or time. The descriptor never contains the OCI digest. The result is
// re-read and verified before it is returned.
func Build(def Definition, root fs.FS, sourceTime time.Time) (*Archive, error) {
	if sourceTime.IsZero() {
		return nil, errors.New("source time is required for a reproducible build")
	}
	sourceTime = sourceTime.UTC().Truncate(time.Second)

	seen := map[string]bool{}
	type entry struct {
		path string
		data []byte
	}
	var entries []entry
	d := &Descriptor{
		Format: FormatV1, Name: def.Name, Version: def.Version, Source: def.Source,
		Policies: def.Policies, Scope: def.Scope, Compatibility: def.Compatibility, OSCAL: def.OSCAL,
	}
	for _, inc := range def.Include {
		if seen[inc.To] {
			return nil, fmt.Errorf("duplicate archive path %q", inc.To)
		}
		seen[inc.To] = true
		if err := validPayloadPath(inc.To); err != nil {
			return nil, err
		}
		if inc.From == "" || path.IsAbs(inc.From) || path.Clean(inc.From) != inc.From || !fs.ValidPath(inc.From) {
			return nil, fmt.Errorf("include %q: from %q must be a clean relative path", inc.To, inc.From)
		}
		data, err := fs.ReadFile(root, inc.From)
		if err != nil {
			return nil, fmt.Errorf("include %q: %w", inc.To, err)
		}
		sum := sha256.Sum256(data)
		d.Files = append(d.Files, File{Path: inc.To, Role: inc.Role, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
		entries = append(entries, entry{inc.To, data})
	}
	sort.Slice(d.Files, func(i, j int) bool { return d.Files[i].Path < d.Files[j].Path })
	if err := d.Validate(); err != nil {
		return nil, err
	}
	desc, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	desc = append(desc, '\n')
	entries = append(entries, entry{DescriptorPath, desc})
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zw.Header = gzip.Header{OS: 255} // unknown OS; no name, comment or mtime
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: e.path, Size: int64(len(e.data)), Mode: 0o644,
			ModTime: sourceTime, Format: tar.FormatPAX,
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	a := &Archive{Descriptor: d, Layer: buf.Bytes()}
	a.LayerDigest = digestOf(a.Layer)
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     manifestMediaType,
		"artifactType":  ArtifactType,
		"config":        map[string]any{"mediaType": EmptyConfigMediaType, "digest": EmptyConfigDigest, "size": 2},
		"layers":        []any{map[string]any{"mediaType": LayerMediaType, "digest": a.LayerDigest, "size": len(a.Layer)}},
	}
	if a.Manifest, err = json.Marshal(manifest); err != nil { // map keys marshal sorted
		return nil, err
	}
	a.ManifestDigest = digestOf(a.Manifest)

	if err := a.verify(); err != nil {
		return nil, fmt.Errorf("built archive failed verification: %w", err)
	}
	return a, nil
}

func (a *Archive) verify() error {
	digest, size, err := ValidateManifest(a.Manifest)
	if err != nil {
		return err
	}
	if digest != a.LayerDigest || size != int64(len(a.Layer)) {
		return errors.New("manifest layer does not describe the archive")
	}
	got, payload, err := Unpack(a.Layer)
	if err != nil {
		return err
	}
	return got.VerifyPayload(payload)
}

// Unpack safely extracts a bundle layer into memory and returns the parsed,
// validated descriptor and the payload (including bundle.json). It rejects
// non-regular entries, duplicate or unsafe paths, and archives exceeding the
// file-count or size limits, so untrusted bytes cannot write or exhaust
// anything outside the returned filesystem.
func Unpack(layer []byte) (*Descriptor, fstest.MapFS, error) {
	zr, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		return nil, nil, fmt.Errorf("gzip: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	files := fstest.MapFS{}
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("tar: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, nil, fmt.Errorf("%s: only regular files are allowed", h.Name)
		}
		if h.Name != DescriptorPath {
			if err := validPayloadPath(h.Name); err != nil {
				return nil, nil, err
			}
		}
		if strings.HasSuffix(h.Name, "/") || files[h.Name] != nil {
			return nil, nil, fmt.Errorf("%s: duplicate or directory entry", h.Name)
		}
		if len(files) >= MaxFiles {
			return nil, nil, fmt.Errorf("more than %d files", MaxFiles)
		}
		total += h.Size
		if h.Size < 0 || total > maxPayloadBytes {
			return nil, nil, fmt.Errorf("payload exceeds %d bytes", maxPayloadBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", h.Name, err)
		}
		if int64(len(data)) != h.Size {
			return nil, nil, fmt.Errorf("%s: short or oversized entry", h.Name)
		}
		files[h.Name] = &fstest.MapFile{Data: data}
	}
	raw, ok := files[DescriptorPath]
	if !ok {
		return nil, nil, fmt.Errorf("archive has no %s", DescriptorPath)
	}
	d, err := ParseDescriptor(raw.Data)
	if err != nil {
		return nil, nil, err
	}
	return d, files, nil
}
